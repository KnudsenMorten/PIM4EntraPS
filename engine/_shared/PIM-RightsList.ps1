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
# SEC-10 mover: the identities that read a secret moved to Key Vault (Get-PimSkvReaderRoles) -- the rows below are built from it
if (-not (Get-Command Get-PimSkvReaderRoles -ErrorAction SilentlyContinue)) {
    $__pimRlSkv = Join-Path $PSScriptRoot 'PIM-SecretsToKeyVault.ps1'
    if (Test-Path -LiteralPath $__pimRlSkv) { . $__pimRlSkv }
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
      no grant set proves nothing. -AllowEmpty: an EMPTY literal (@{}) is a real, deliberate set -- the web identity's Graph set
      is empty since 3.1.42 (GRAPH-PICKER: the pickers read PIM's database); a missing or non-literal map still throws.
    #>
    param([Parameter(Mandatory)][string]$Variable, [string]$Path = (Join-Path (Get-PimRightsListRoot) 'tools\setup\_PimSetupShared.ps1'), [switch]$AllowEmpty)
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
    if (-not $map.Count -and -not $AllowEmpty) { throw "$Variable in $Path is empty" }
    return $map
}

function Get-PimRightsCodeGraphSets {
    <#
      PURE (reads the grant files). The Graph application permissions the CODE grants, per identity role:
        @{ engine = <name -> id>; web = ...; updater = ...; downlink = ... }   (ordered name -> appRole id)
    #>
    param([string]$SetupSharedPath = (Join-Path (Get-PimRightsListRoot) 'tools\setup\_PimSetupShared.ps1'))
    $engine = Get-PimRightsSetupMapFromSource -Variable '$script:PimGraphAppRoles' -Path $SetupSharedPath
    # GRAPH-PICKER (2026-11-17): the web identity's Graph set is EMPTY -- the pickers and lookups read PIM's database
    $web = Get-PimRightsSetupMapFromSource -Variable '$script:PimGraphAppRolesManager' -Path $SetupSharedPath -AllowEmpty
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
        # 2026-11-17: no updater purpose text for the PIM-for-Groups rights (PrivilegedAssignmentSchedule, RoleManagementPolicy) -- the
        # updater holds no PIM-for-Groups right since framework G5a (3.1.26), and its SQL admin group step is retired
        'updater|GroupMember.Read.All'                                = 'Reads the SQL admin group and the database job identity''s memberships, and the web identity''s group memberships for its trim (read only)'
        'updater|Application.Read.All'                                = 'Reads the database job identity''s service principal memberships, and the web identity''s app roles and memberships for its trim (read only)'
        'updater|Application.ReadWrite.OwnedBy'                       = 'Changes only the PIM app registrations it owns'
        'updater|User.ReadBasic.All'                                  = 'Reads the SuperAdmins'' mail addresses for the alert recipients (basic profile only)'
        # GRAPH-PICKER (2026-11-17): no 'web|...' entry -- the web identity holds no Graph permission (the pickers and the user /
        # group lookups read PIM's database, written by the engine; proven live on 3.1.40 / 3.1.41)
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
        # SEC-10 (framework 4 "secrets in Key Vault only"; Invardia ruling 2026-11-11): on once the install's secrets were moved to
        # Key Vault references (tools\setup\Move-PimSecretsToKeyVault.ps1) -- before that no identity holds the right.
        'secrets-in-keyvault' = 'The install''s secrets were moved into its own Key Vault (Move-PimSecretsToKeyVault.ps1): the apps and jobs read them as Key Vault references with their own identity. Not a catalog gate -- the setup step keyvault-secrets-only reports it.'
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
    $rows = @(
        # ---- engine (the engine job's identity)
        (& $r 'engine' 'reader@subscription' 'azure-rbac' 'Reader' $reader 'subscription' 'the hosting subscription' 'always' '' 'Reads Azure in the hosting subscription (Discovery, the Azure half of the tenant cache)' 'tools\setup\Setup-PimContainers.ps1 Grant-PimMiAzureRbac (-AzureRbacRoles default Reader; Get-PimAzureRbacPlan scope /subscriptions/<sub>)')
        (& $r 'engine' 'reader@tenant-root' 'azure-rbac' 'Reader' $reader 'tenant-root' 'the Tenant Root Group (its id is the tenant id)' 'always' '' 'Discovery lists management groups and subscriptions (read only)' 'tools\setup\_PimSetupShared.ps1 Get-PimEngineRootAzurePlan / Grant-PimEngineRootAzureAccess (PIM 97)')
        (& $r 'engine' 'reader@engine-job' 'azure-rbac' 'Reader' $reader 'resource' 'the engine job itself (caj-pim-engine / ca-pim-tick)' 'always' '' 'Reads its own job executions (one engine run at a time)' 'tools\setup\Initialize-PimHostingAccess.ps1 (Reader on the tick job)')
        (& $r 'engine' 'container-apps-jobs-operator@updater-job' 'azure-rbac' 'Container Apps Jobs Operator' $jobsOp 'resource' 'the updater job only' 'always' '' 'The engine starts the updater for "update now" (update-expedite) and reads its executions' 'tools\setup\_PimSetupShared.ps1 Grant-PimEngineUpdaterJobAccess (Deploy-PimUpdateJob.ps1, Initialize-PimHostingAccess.ps1); owner rights decision 2026-11-09 "approved with A"')
        (& $r 'engine' 'contributor@updater-job' 'azure-rbac' 'Contributor' $contrib 'resource' 'the updater job only' 'always' '' 'The watchdog restores the updater job to its last good image' 'tools\setup\_PimSetupShared.ps1 Grant-PimEngineUpdaterJobAccess (Deploy-PimUpdateJob.ps1, Initialize-PimHostingAccess.ps1); owner rights decision 2026-11-09 "approved with A"')
        (& $r 'engine' 'user-access-administrator@defined-scopes' 'azure-rbac' 'User Access Administrator' $uaa 'subscription' 'each top Azure scope the store defines (subscription, management group or resource group of PIM-Assignments-Azure-Resources / PIM-Definitions-Resources) -- never Owner' 'feature' 'azure-rbac' 'Assigns Azure resource roles (eligible / active) and sets their PIM policies where Azure delegations are defined' 'engine\_shared\PIM-EngineAzureAccess.ps1 (95.2k) + engine\_shared\PIM-EngineAzureScopeTrim.ps1 (4.3); tools\setup\_PimWorkloadPrereqRunner.ps1 Invoke-PimPrereqAzureRbac')
        (& $r 'engine' 'user-access-administrator@tenant-root' 'azure-rbac' 'User Access Administrator' $uaa 'tenant-root' 'only with the install opt-in -EngineAzureRootUserAccessAdmin; then it replaces the per-scope grants' 'feature' 'azure-rbac' 'Assigns Azure resource roles at every subscription (opt-in)' 'tools\setup\_PimSetupShared.ps1 Get-PimEngineRootAzurePlan -IncludeUserAccessAdministrator')
        (& $r 'engine' 'storage-table-data-contributor@rfa-store' 'azure-rbac' 'Storage Table Data Contributor' $stdc 'resource' 'the RFA broker''s storage account' 'feature' 'rfa.portal' 'Pulls the requests and answers of the RFA portal / access request API' 'tools\setup\_PimRfaBrokerPlan.ps1 (role-engine-<id>), tools\setup\Deploy-PimRfaBroker.ps1')
        # 2026-11-17 (owner kept it 2026-11-13): the engine's ONE custom role. A managing tenant whose bundle store is reached over
        # the internet (access publicSigned) lets the engine set that store's network rules for the enrolled tenants. Its role
        # definition is created per install (a new guid, the storage account in its name), so the row has NO roleId: it is
        # matched by its NAME PREFIX (Get-PimRightsCustomRolePrefix / Test-PimRightsRoleNameMatch).
        (& $r 'engine' 'bundle-store-network-rules@bundle-store' 'azure-rbac' 'PIM Manager bundle store network rules - <account>' '' 'resource' 'the managing tenant''s bundle store (one storage account) only, and only when that store is reached over the internet (access publicSigned); a custom role with Microsoft.Storage/storageAccounts/read + write only -- no data access, no keys. Its id differs per install: matched by the name prefix' 'feature' 'msp.downlink' 'The enrolled-tenants job reads the bundle store and sets its network rules, so each enrolled managed tenant can reach the signed bundle' 'tools\setup\Publish-PimEnrollmentFacts.ps1 (step enrollment, -Access publicSigned: creates the custom role and assigns it to the engine); used by engine\msp\PIM-InvardiaEnrollment.ps1 Invoke-PimEnrolledTenantsJob')
        (& $r 'engine' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls the engine image' 'tools\setup\Setup-PimContainers.ps1 (AcrPull per workload identity); engine\_shared\PIM-IdentityMove.ps1 Get-PimIdentityMoveRoleNeeds')
        (& $r 'engine' 'fabric-administrator@tenant' 'entra-directory-role' 'Fabric Administrator' $fabric 'tenant' 'directory scope / (active, permanent); older tenants show it as Power BI Administrator' 'feature' 'connectors.powerbi' 'Gives Power BI workspace roles through the Fabric admin API' 'tools\setup\_PimWorkloadPrereqRunner.ps1 (powerbi.fabricAdmin, Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator)')
        # ---- web (the web app's identity)
        (& $r 'web' 'reader@install-rg' 'azure-rbac' 'Reader' $reader 'install-rg' 'the PIM resource group only (never the subscription)' 'always' '' 'The Environment report reads the installation''s own architecture' 'tools\setup\_PimSetupShared.ps1 Get-PimManagerRgReaderScope / Grant-PimManagerRgReader (PIM 100.22 b, RIGHTS-1 B)')
        # SECURE-WEB-1 (framework 12.11f, 2026-11-14): the web identity holds NO job right any more (it was 'Container Apps Jobs
        # Operator' on the engine job: a job start accepts a container override, so the internet-facing app could run a command
        # as the engine). Commit / Run now wait for the next scheduled start of the engine job.
        # SECURE-WEB-1 (3.1.26, owner: "the internet-facing identity has NO Key Vault edge"): the web holds NO Key Vault role. The
        # signin-front container is retired fleet-wide (its Key Vault Crypto Service Encryption User on the key signin-front went
        # with it) and the break-glass check reads a verifier in the PIM database (its Key Vault Secrets User on the one secret
        # PIM-EmergencyPasscode went too). What it gains is a DATA role on its OWN data: the token store of Microsoft's built-in
        # sign-in (one blob container, not the account) -- not a never-right, so the SECURE-WEB-1 lint stays green.
        (& $r 'web' 'storage-blob-data-contributor@token-store-container' 'azure-rbac' 'Storage Blob Data Contributor' $sbdc 'resource' 'the token-store container pim-auth-tokens in the install''s storage account only (not the account)' 'always' '' 'Microsoft''s built-in sign-in in front of the web app keeps its sign-in tokens there (the token store)' 'tools\setup\Set-PimManagerEasyAuth.ps1 (the token store: Storage Blob Data Contributor on the container pim-auth-tokens)')
        (& $r 'web' 'acrpull@registry' 'azure-rbac' 'AcrPull' $acr 'resource' 'the install''s container registry' 'feature' 'own-registry-pull' 'Pulls the web app image' 'tools\setup\Setup-PimContainers.ps1 (AcrPull per workload identity)')
        # ---- updater (the update job's identity)
        (& $r 'updater' 'contributor@install-rg' 'azure-rbac' 'Contributor' $contrib 'install-rg' 'the PIM resource group only; also on the registry itself when it lives in another resource group' 'always' '' 'Rolls the web app and the jobs to the approved image and builds it in the registry; after a healthy update deletes the images older than the previous release from the install''s own registry (IMAGE-PRUNE); after the roll reads the web identity''s role assignments for its trim (WEB-TRIM-1) -- it removes none with this role (Contributor cannot delete a role assignment), they are reported' 'tools\setup\Deploy-PimUpdateJob.ps1 (step 2)')
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
    # ---- SEC-10 (framework 4 "secrets in Key Vault only"; Invardia ruling 2026-11-11): Key Vault Secrets User at the install's
    # own vault (resource scope) for EXACTLY the identities that read a moved secret -- GENERATED from the mover's own reader
    # set (engine\_shared\PIM-SecretsToKeyVault.ps1 Get-PimSkvReaderRoles, code role keys; asbuilt is the docs identity)
    if (-not (Get-Command Get-PimSkvReaderRoles -ErrorAction SilentlyContinue)) { throw 'Get-PimSkvReaderRoles is not loaded (engine\_shared\PIM-SecretsToKeyVault.ps1)' }
    $cat = @(Get-PimRightsIdentityCatalog)
    foreach ($cr in @(Get-PimSkvReaderRoles)) {
        $id = @($cat | Where-Object { $_.codeRole -eq $cr })[0]
        if (-not $id) { throw "Get-PimSkvReaderRoles names '$cr', which is no identity of the rights list" }
        $rows += (& $r $id.role 'key-vault-secrets-user@install-vault' 'azure-rbac' (Get-PimSkvRoleName) (Get-PimSkvRoleId) 'resource' 'the install''s own Key Vault' 'feature' (Get-PimSkvFeatureKey) 'Reads its own secrets as Key Vault references (once they were moved into the install''s Key Vault)' 'tools\setup\Move-PimSecretsToKeyVault.ps1 (engine\_shared\PIM-SecretsToKeyVault.ps1 Invoke-PimSkvGrant; Get-PimSkvReaderRoles)')
    }
    # SEC-10 (Invardia decision 2026-11-11): the WRITER -- the install's own updater writes the moved secrets inside its update run
    # (Invoke-PimSkvUpdaterStep); granted once by the Support-app step (Move-PimSecretsToKeyVault.ps1 -GrantOnly), never by itself
    $wr = @($cat | Where-Object { $_.codeRole -eq (Get-PimSkvWriterRole) })[0]
    if (-not $wr) { throw "Get-PimSkvWriterRole names '$(Get-PimSkvWriterRole)', which is no identity of the rights list" }
    $rows += (& $r $wr.role 'key-vault-secrets-officer@install-vault' 'azure-rbac' (Get-PimSkvOfficerRoleName) (Get-PimSkvOfficerRoleId) 'resource' 'the install''s own Key Vault' 'feature' (Get-PimSkvFeatureKey) 'Writes the install''s secrets into its own Key Vault and switches the apps and jobs to Key Vault references (the update run''s secrets step); granted once by the Support app' 'engine\_shared\PIM-SecretsToKeyVault.ps1 Invoke-PimSkvUpdaterStep (tools\pim-engine\update-job-entry.ps1 step 2f-ter); granted by tools\setup\Move-PimSecretsToKeyVault.ps1 -GrantOnly')
    # SECURE-WEB-1 (3.1.26): no row for the web on the secret PIM-EmergencyPasscode any more -- the break-glass check reads the
    # verifier in the PIM database (engine\_shared\PIM-EmergencyVerifier.ps1); Set-PimEmergencyPassphrase.ps1 makes no grant.
    # ---- WAKE-1 (3.1.26, framework SECURE-WEB-1 point 1): the wake queue 'pim-wake' -- ONE queue in the install's own storage
    # account. The web may only SEND a message (a job name) to it; the wake job, which runs as the ENGINE identity, reads and
    # deletes it and the platform counts it. Granted by setup (Deploy-PimWakeJob.ps1); the updater only reports a missing one.
    $wkSrc = 'tools\setup\Deploy-PimWakeJob.ps1 (engine\_shared\PIM-Wake.ps1 Invoke-PimWakeConverge -Grant, Get-PimWakeRoleIds)'
    $wkScope = 'the wake queue pim-wake in the install''s own storage account only (not the account)'
    $rows += (& $r 'web' 'storage-queue-data-message-sender@wake-queue' 'azure-rbac' 'Storage Queue Data Message Sender' 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a' 'resource' $wkScope 'always' '' 'Commit / Run now put one wake message (the job name only) on the wake queue, so the engine starts within a minute' $wkSrc)
    $rows += (& $r 'engine' 'storage-queue-data-message-processor@wake-queue' 'azure-rbac' 'Storage Queue Data Message Processor' '8a0f0c08-91a1-4084-bc3d-661d67233fed' 'resource' $wkScope 'always' '' 'The wake job (caj-pim-wake, as the engine identity) reads and deletes the wake message, checks its age and name, then runs the engine once' $wkSrc)
    $rows += (& $r 'engine' 'storage-queue-data-reader@wake-queue' 'azure-rbac' 'Storage Queue Data Reader' '19e7f393-937e-4f77-808e-94535e297925' 'resource' $wkScope 'always' '' 'The platform counts the wake messages (event trigger) to start the wake job' $wkSrc)
    # ---- MANAGER-CHAT-1 (3.1.26): the chat in the Manager calls Azure OpenAI KEYLESSLY as the web identity. An outbound,
    # inference-only data role on ONE Azure OpenAI resource (the one named in Settings AiChat); no key, no management right.
    # Granted by the operator on that resource, never by PIM's code; Set-PimAiChat.ps1 / the chat readiness check only report it.
    $rows += (& $r 'web' 'cognitive-services-openai-user@ai-chat-resource' 'azure-rbac' 'Cognitive Services OpenAI User' '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd' 'resource' 'the one Azure OpenAI resource the AI chat settings name (not a subscription or resource group)' 'feature' 'ai.chat' 'The chat in the Manager sends the person''s question and the read results of their own role to the model, keyless' 'tools\setup\Set-PimAiChat.ps1 (readiness check only; the grant is made on the Azure OpenAI resource by the operator)')
    return $rows
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
    # internetFacing (SECURE-WEB-1 point 4): the identity of an app WITH INGRESS -- web = ca-pim-manager (the Manager; its
    # signin-front container is retired, 3.1.26), requests = the RFA broker app (public portal). In Container Apps every container of an app can
    # take every identity assigned to that app, so these identities may hold only their own data (Get-PimRightsNeverRules).
    return @(
        [ordered]@{ role = 'engine';   codeRole = 'engine';   oldNames = @();                  graph = 'engine';   when = 'always';  featureKey = '';             internetFacing = $false }
        [ordered]@{ role = 'web';      codeRole = 'web';      oldNames = @();                  graph = 'web';      when = 'always';  featureKey = '';             internetFacing = $true }
        [ordered]@{ role = 'updater';  codeRole = 'updater';  oldNames = @();                  graph = 'updater';  when = 'always';  featureKey = '';             internetFacing = $false }
        [ordered]@{ role = 'downlink'; codeRole = 'downlink'; oldNames = @();                  graph = 'downlink'; when = 'feature'; featureKey = 'msp.downlink'; internetFacing = $false }
        [ordered]@{ role = 'publish';  codeRole = 'publish';  oldNames = @();                  graph = '';         when = 'feature'; featureKey = 'msp.downlink'; internetFacing = $false }
        [ordered]@{ role = 'requests'; codeRole = 'requests'; oldNames = @();                  graph = '';         when = 'feature'; featureKey = 'rfa.portal';   internetFacing = $true }
        [ordered]@{ role = 'dbinit';   codeRole = 'dbinit';   oldNames = @();                  graph = '';         when = 'always';  featureKey = '';             internetFacing = $false }
        [ordered]@{ role = 'docs';     codeRole = 'asbuilt';  oldNames = @('id-pim-asbuilt');  graph = '';         when = 'always';  featureKey = '';             internetFacing = $false }
    )
}

function Get-PimRightsNeverRules {
    <#
      PURE. SECURE-WEB-1 (framework 12.11f, owner 2026-11-14): the rights an INTERNET-FACING identity must never hold -- each
      one lets a compromised web container reach beyond its own data. Matched on the role id (Azure built-ins) and, for Graph,
      on the permission name; an Azure role also by its NAME (azureRoleName), so a built-in whose id is not listed here (any
      Container Apps job role, any Contributor of the compute plane) is still caught. A data role on the identity's own data
      (Storage Table / Blob Data Contributor on its own table / container) is not a never-right. SECURE-WEB-1 (3.1.26): ANY
      Key Vault role is a never-right (azureRoleName '\bkey vault\b') -- an internet-facing identity has no Key Vault edge.
      Returns @{ azureRoleIds = @{ id = name }; azureRoleName = regex; graphPattern = regex }.
    #>
    return @{
        azureRoleName = '(?i)(\bjobs?\b|^owner$|^contributor$|container apps contributor|managedenvironments contributor|user access administrator|role based access control administrator|^acrpush$|\bkey vault\b|managed identity (operator|contributor))'
        azureRoleIds = [ordered]@{
            'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' = 'Container Apps Jobs Operator'
            'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
            '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
            '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
            'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
            '8311e382-0749-4cb8-b61a-304f252e45ec' = 'AcrPush'
            '4633458b-17de-408a-b874-0445c86b69e6' = 'Key Vault Secrets User'
            'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
            '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
            'f25e0fa2-a7c8-4377-a976-54943a77a395' = 'Key Vault Contributor'
            'f1a07417-d97a-45cb-824c-7a7467783830' = 'Managed Identity Operator'
            # framework SECURE-WEB-1 point 4 (Invardia, from SI's review 2026-11-14)
            'e40ec5ca-96e0-45a2-b4ff-59039f2c2b59' = 'Managed Identity Contributor'
            '8b54135c-b56d-4d72-a534-26097cfdc8d8' = 'Key Vault Data Access Administrator'
            '57cc5028-e6a7-4284-868d-0611c5923f8d' = 'Container Apps ManagedEnvironments Contributor'
        }
        graphPattern = '(?i)(ReadWrite|\.Write|Manage|\.Send|FullControl)'
    }
}

function Get-PimRightsNeverExceptions {
    <#
      PURE. LITERAL. The never-rights an internet-facing identity may still hold -- EMPTY since 3.1.26 (SECURE-WEB-1, owner: "the
      internet-facing identity has NO Key Vault edge"). The one exception there was (Invardia 2026-11-14 F1 b: the web's Key Vault
      Secrets User on the secret PIM-EmergencyPasscode) is gone: the break-glass check reads a verifier in the PIM database. Every
      never-right now fails the gate; this list only shrinks, so it stays empty.
    #>
    return @()
}

function Test-PimRightsInternetFacing {
    <#
      PURE. The SECURE-WEB-1 lint over an approved rights list: every right of an internetFacing identity that is a never-right.
      Returns @{ violations = @(<right id = role>); excepted = @(<right id = role>) }. The gate fails on any violation.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$List)
    $rules = Get-PimRightsNeverRules; $exc = @(Get-PimRightsNeverExceptions)
    $bad = New-Object System.Collections.Generic.List[string]; $okx = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($List.identities)) {
        if (-not [bool]$id.internetFacing) { continue }
        foreach ($rt in @($id.rights)) {
            $never = $false
            if ("$($rt.kind)" -eq 'graph-app-role') { $never = ("$($rt.role)" -match $rules.graphPattern) }
            elseif ("$($rt.kind)" -eq 'entra-directory-role') { $never = $true }
            else { $never = ($rules.azureRoleIds.Contains("$($rt.roleId)".ToLowerInvariant()) -or "$($rt.role)" -match $rules.azureRoleName) }
            if (-not $never) { continue }
            $line = "$($rt.id) = $($rt.role)"
            if ($exc -contains "$($rt.id)") { $okx.Add($line) } else { $bad.Add($line) }
        }
    }
    return @{ violations = @($bad); excepted = @($okx) }
}

function Get-PimRightsCustomRolePrefix {
    <#
      PURE. A CUSTOM role in the list is named with a placeholder for the per-install part ('<name> - <account>'): its role
      definition is created per install (a new id), so it is matched by the text BEFORE the placeholder. Returns that prefix
      ('PIM Manager bundle store network rules - '), or '' for a built-in role (matched exactly, by id).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Role)
    $i = "$Role".IndexOf('<')
    if ($i -le 0 -or "$Role" -notmatch '<[A-Za-z0-9 _-]+>\s*$') { return '' }
    return "$Role".Substring(0, $i)
}

function Test-PimRightsRoleNameMatch {
    <#
      PURE. Does a HELD role name match a LISTED one? A built-in: the same name (case-insensitive). A custom role (a listed name
      with a placeholder): the held name starts with the listed prefix and has a non-empty per-install part.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Listed, [AllowEmptyString()][AllowNull()][string]$Held)
    $h = "$Held".Trim(); if (-not $h) { return $false }
    $p = Get-PimRightsCustomRolePrefix -Role $Listed
    if ($p) { return ($h.Length -gt $p.Length -and $h.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) }
    return ($h -ieq "$Listed".Trim())
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
            $o = [ordered]@{ id = $rid; kind = $a.kind; role = $a.role }
            # a custom role (its id differs per install) carries no roleId: it is matched by its name prefix
            if ("$($a.roleId)".Trim()) { $o['roleId'] = $a.roleId }
            $o['scope'] = $a.scope
            if ("$($a.scopeNote)".Trim()) { $o['scopeNote'] = $a.scopeNote }
            $o['when'] = $a.when
            if ($a.when -eq 'feature') { $o['featureKey'] = $a.featureKey }
            $o['feature'] = $a.feature
            $rights[$rid] = $o
        }
        $ids = Get-PimRightsSortedOrdinal -Items @($rights.Keys)
        $old = Get-PimRightsSortedOrdinal -Items @($id.oldNames)
        $byRole[$id.role] = [ordered]@{ role = $id.role; name = "id-pim-$($id.role)"; oldNames = $old; internetFacing = [bool]$id.internetFacing; rights = @(foreach ($k in $ids) { $rights[$k] }) }
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
