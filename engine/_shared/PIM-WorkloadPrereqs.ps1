<#
  REQ-U (prereqs) -- WORKLOAD PREREQUISITES: one definition, used by the setup script, the Manager and the tests.

  Operator, 2026-09-19, in order: "make prereqscript that i must run per workload"; "dont put in template";
  "refer to script in gui and show with green if prereq has run".

  WHAT THIS FILE IS. The CATALOG of every prerequisite per workload (stable check ids, names, whether an API can
  check / fix it, the exact portal step when only a human can, the Microsoft Learn link) plus the PURE verdicts the
  setup script feeds facts into. It never calls Graph / ARM / Fabric and never reads SQL or the clock on its own.
    * tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload <X>  -- gathers the facts, fixes what an API can fix,
      writes pim.Settings 'WorkloadPrereqs' (tools\setup\_PimWorkloadPrereqRunner.ps1 holds its live half).
    * tools\pim-manager\Open-PimManager.ps1 GET /api/workload-prereqs -- Get-PimWorkloadPrereqView (below) turns the
      stored record into green / amber / red chips with the exact command to run.
    * tests\Test-PimWorkloadPrereqs.ps1 -- the same definitions, offline.
    * REQ-W (2.4.380) -- the ASSIGNMENT gate (Get-PimWorkloadAssignmentGate): the engine (PIM-WorkloadRoles.ps1
      Get-PimWorkloadAssignmentHold) holds a NEW workload role assignment while its workload is not green; the Manager
      and the GUI only SAY so. Nothing is refused at staging and every group is created.
    * §97.1 (owner 2026-10-08: "we dont support certificates ... does the engine not have the necessary permissions for
      this") -- the SELF-CHECK: the tick job 'workload-prereqs' (engine\_shared\PIM-WorkloadPrereqSelfCheck.ps1) runs every
      check an API can answer AS THE ENGINE ITSELF, daily and on "Check again", and records it here (ranBy 'engine
      self-check'), MERGED with what a person recorded (Merge-PimWorkloadPrereqRecord): a portal confirmation is kept, a
      verified result the engine cannot read itself is kept. Portal-only steps are confirmed in the Manager
      (Set-PimWorkloadPrereqAttestation, POST /api/workload-prereqs/confirm). A fix that needs a grant is the published
      browser-sign-in script (Get-PimWorkloadPrereqFixCommand) -- never a certificate command.

  🔒 TEMPLATES STAY CLEAN. No prerequisite is written into templates\*.template.json; the template -> workload mapping
  lives HERE (Get-PimWorkloadPrereqTemplateMap), so a pack is only rows.

  STATUS VOCABULARY (one word per check; "not checked" is never "ok", wave-2 rule 7):
    ok          -- verified by an API call just now
    fixed       -- was missing, this run fixed it through an API and READ IT BACK
    confirmed   -- a portal-only step the operator attested with -ConfirmPortalStep (not API-verifiable; says so)
    skipped     -- deliberately not applicable (e.g. -SkipDataOperations); recorded with the reason
    failed      -- verified missing
    manual      -- a portal-only step nobody has confirmed yet
    notChecked  -- could not be read (403 for the CALLER, feature off, no identity to test as) -- reason in detail
  A workload is 'ok' when every REQUIRED check is ok / fixed / confirmed / skipped; 'failed' when any required check
  failed; otherwise 'incomplete'. Optional checks (a confirmation such as the Power BI admin-API test GET, which can
  only run where the engine's own credential is on this host) are reported but never decide the state.

  PS 5.1-safe (setup scripts run on Windows PowerShell 5.1): no ?. / ?? / ternary.
#>

Set-StrictMode -Off
# SCRIPT-DOC-1 (framework 12.7 + 12.10 item 11): every command this file builds for a person to run comes from the ONE
# command form in tools\setup\_PimScriptDoc.ps1 -- line 1 download, line 2 run (owner 2026-10-11; doc page linked next to it).
. (Join-Path $PSScriptRoot '..\..\tools\setup\_PimScriptDoc.ps1')

# --- Learn links (cited, 2026-09-19) -----------------------------------------------------------------------------
function Get-PimPrereqLearnLinks {
    # A FUNCTION, not a $script: table: a dot-sourced file's $script: binds to whoever CALLS it (PIM-Rest.ps1's trap note).
    @{
    urbacActivate  = 'https://learn.microsoft.com/en-us/defender-xdr/activate-defender-rbac'
    urbacPerms      = 'https://learn.microsoft.com/en-us/defender-xdr/custom-permissions-details'
    sentinelOnboard = 'https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard'
    sentinelState   = 'https://learn.microsoft.com/en-us/rest/api/securityinsights/sentinel-onboarding-states/get'
    sentinelDefender= 'https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-onboard'
    graphPerms      = 'https://learn.microsoft.com/en-us/graph/permissions-reference'
    intuneRbac      = 'https://learn.microsoft.com/en-us/intune/fundamentals/role-based-access-control/overview'
    fabricSpAdmin   = 'https://learn.microsoft.com/en-us/fabric/admin/enable-service-principal-admin-apis'
    fabricList      = 'https://learn.microsoft.com/en-us/rest/api/fabric/admin/tenants/list-tenant-settings'
    fabricUpdate    = 'https://learn.microsoft.com/en-us/rest/api/fabric/admin/tenants/update-tenant-setting'
    azureRoles      = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/privileged'
    pimLicense      = 'https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals'
    }
}

function Get-PimWorkloadPrereqWorkloads {
    # The workloads the setup script accepts, in display order.
    @('DefenderXdr', 'Intune', 'PowerBI', 'AzureRbac', 'EntraRoles')
}

function Get-PimWorkloadPrereqStaleDays { 30 }

function Get-PimWorkloadPrereqGraphRoleIds {
    # Built-in / well-known ids used by the verdicts. Azure role definition ids are Microsoft's built-in ids
    # (Learn: built-in-roles/privileged); the two first-party appIds are the Microsoft Graph and Power BI Service
    # service principals every tenant has.
    @{
        graphAppId           = '00000003-0000-0000-c000-000000000000'
        powerBiAppId         = '00000009-0000-0000-c000-000000000000'
        userAccessAdmin      = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
        owner                = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        rbacAdministrator    = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168'
        reader               = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
    }
}

function Get-PimWorkloadPrereqCatalog {
    <#
      The ONE definition of every prerequisite. Returns an ordered map workload -> @{ workload; title; checks }.
      Each check: id (stable, stored), name, kind (api | portal), required, fixable, fix (what the script does when it
      fixes it), manualStep (exact portal path, for a human), learn (Microsoft Learn), dataOperations (Defender Data
      Operations only -- honoured by -SkipDataOperations).
      -Workload narrows to one (throws on an unknown name: a typo must not look like "no prerequisites").
    #>
    [CmdletBinding()] param([string]$Workload)
    $L = Get-PimPrereqLearnLinks
    $c = [ordered]@{}
    $c['DefenderXdr'] = @{ workload = 'DefenderXdr'; title = 'Microsoft Defender XDR (Unified RBAC)'; checks = @(
        @{ id = 'defender.engineRole'; name = 'Engine identity holds Graph RoleManagement.ReadWrite.Defender'; kind = 'api'; required = $true; fixable = $true
           fix = 'grants the Microsoft Graph application role to the engine identity (id from the one role map, verified against the live Graph service principal) and reads it back'
           manualStep = 'An administrator grants it with the published Grant-PimEnginePermissions.ps1 (browser sign-in, no PowerShell modules) -- PIM Manager shows the exact command on this prerequisite and on Overview. PIM never grants itself a permission.'
           learn = "$($L.graphPerms)#rolemanagementreadwritedefender" }
        @{ id = 'defender.urbacReachable'; name = 'Unified RBAC answers (Graph beta roleManagement/defender/roleDefinitions = 200)'; kind = 'api'; required = $true; fixable = $false
           fix = ''
           manualStep = 'Activate Unified RBAC: Microsoft Defender portal (security.microsoft.com) > System > Permissions > Microsoft Defender XDR > Roles > Activate workloads (or Workload settings). Needs Security Administrator. Portal only -- Microsoft publishes no API for activation.'
           learn = $L.urbacActivate }
        @{ id = 'defender.urbacWorkloads'; name = 'The workloads PIM delegates are activated for Unified RBAC'; kind = 'portal'; required = $true; fixable = $false
           fix = ''
           manualStep = 'Microsoft Defender portal > System > Permissions > Microsoft Defender XDR > Roles > Workload settings: turn on every workload PIM delegates (Endpoint, Identity, Office 365, Sentinel workspaces via View Workspaces) > Activate. Portal only: no API exposes the activation state, so PIM reports what the live roles imply ("inferred") and you confirm it with Confirm on this prerequisite in PIM Manager.'
           learn = $L.urbacActivate }
        # Measured by the lead on internal 2026-09-19 (read-only): the catalog GET beta/roleManagement/defender/
        # resourceNamespaces?$expand=resourceActions answers 200 with 77 actions, microsoft.xdr/dataops/*/read|manage among
        # them -- and a tenant WITHOUT the Sentinel prerequisite still LISTS them but REFUSES to store a role using them
        # (POST roleDefinitions -> 400 "... is not a valid permission for storage"). So "Data Operations available" =
        # this catalog check AND the Sentinel checks below. Never probed by creating a role (no probe writes).
        @{ id = 'defender.dataOpsCatalog'; name = 'Data Operations permissions are in the Defender permission catalog (beta resourceNamespaces lists microsoft.xdr/dataops/)'; kind = 'api'; required = $true; fixable = $false; dataOperations = $true
           fix = ''
           manualStep = 'Data Operations (Preview) is a Unified RBAC permission group that follows Microsoft Sentinel: measured on three tenants, the catalog listed microsoft.xdr/dataops/ only where Sentinel was enabled. Not listed? Do the Sentinel checks below (enable Sentinel on a workspace, connect it to the Defender portal), then press Check again. Listed but a role using it is refused? The Defender-portal connection below is missing.'
           learn = $L.urbacPerms }
        # confirmable 'notChecked' (§97.1): the engine's self-check only sees the workspaces it has Reader on, so "none
        # found" is NOT CHECKED there -- an administrator who knows the security workspace has Sentinel confirms it.
        @{ id = 'defender.sentinelEnabled'; name = 'Microsoft Sentinel is enabled on a Log Analytics workspace (ARM onboardingStates/default = 200)'; kind = 'api'; required = $true; fixable = $false; dataOperations = $true; confirmable = 'notChecked'
           fix = ''
           manualStep = "Azure portal > Microsoft Sentinel > Create > choose the Log Analytics workspace > Add; then onboard it to the Defender portal (next check). If PIM cannot see your security workspace, press Confirm on this prerequisite in PIM Manager. Or run the published Initialize-PimWorkloadPrereqs.ps1 with -EnableSentinel (opt-in, because Sentinel bills per GB the workspace ingests): it enables Sentinel on a dedicated security workspace -- -SentinelWorkspaceId, else law-sentinel-<suffix> in the PIM resource group, created empty -- and refuses PIM's own log workspace. Pass -SentinelWorkspaceId <workspace resource id> to check or enable a specific one. Data Operations prerequisites: $($L.urbacPerms) and $($L.sentinelDefender)"
           learn = $L.sentinelOnboard }
        @{ id = 'defender.sentinelInDefender'; name = 'Data Operations: a Sentinel workspace is connected to the Defender portal (or the Sentinel data lake is onboarded)'; kind = 'portal'; required = $true; fixable = $false; dataOperations = $true
           fix = ''
           manualStep = "Microsoft Defender portal > System > Settings > Microsoft Sentinel > Workspaces > Connect a workspace (pick the primary workspace), or onboard the Microsoft Sentinel data lake from the Defender portal. Portal only (no public API). Until this is done the tenant LISTS the Data Operations permissions but refuses to store a role that uses them. Then press Confirm on this prerequisite in PIM Manager. Not using Data Operations roles? Press Not used. Learn: $($L.urbacPerms)"
           learn = $L.sentinelDefender }
    ) }
    $c['Intune'] = @{ workload = 'Intune'; title = 'Microsoft Intune (RBAC roles)'; checks = @(
        @{ id = 'intune.engineRole'; name = 'Engine identity holds Graph DeviceManagementRBAC.ReadWrite.All'; kind = 'api'; required = $true; fixable = $true
           fix = 'grants the Microsoft Graph application role to the engine identity (the one role map) and reads it back'
           manualStep = 'An administrator grants it with the published Grant-PimEnginePermissions.ps1 (browser sign-in, no PowerShell modules) -- PIM Manager shows the exact command on this prerequisite and on Overview. PIM never grants itself a permission.'
           learn = "$($L.graphPerms)#devicemanagementrbacreadwriteall" }
        @{ id = 'intune.rbacReadable'; name = 'Intune RBAC answers (Graph deviceManagement/roleDefinitions = 200)'; kind = 'api'; required = $true; fixable = $false
           fix = ''
           manualStep = 'Intune RBAC needs no activation, but the tenant needs an Intune licence. Microsoft Intune admin center (intune.microsoft.com) > Tenant administration > Roles shows the roles once it is licensed.'
           learn = $L.intuneRbac }
    ) }
    $c['PowerBI'] = @{ workload = 'PowerBI'; title = 'Power BI / Fabric (workspace roles)'; checks = @(
        @{ id = 'powerbi.group'; name = 'The security group for Fabric admin-API access exists'; kind = 'api'; required = $true; fixable = $true
           fix = 'creates the security group through Graph (securityEnabled, not mail-enabled) and reads it back'
           manualStep = 'Microsoft Entra admin center > Groups > New group > Group type: Security > Group name: grp-pim-powerbi-admin-api (the name PIM looks for) > Members: the engine identity > Create. PIM Manager names the group and the identity, with its object id, on this prerequisite once it has checked.'
           learn = $L.fabricSpAdmin }
        @{ id = 'powerbi.groupMember'; name = 'The engine identity is a member of that group'; kind = 'api'; required = $true; fixable = $true
           fix = 'adds the engine identity to the group through Graph and reads the membership back'
           manualStep = 'Microsoft Entra admin center > Groups > grp-pim-powerbi-admin-api > Members > Add members > the engine identity (search for its object id). PIM Manager names the group and the identity, with its object id, on this prerequisite once it has checked.'
           learn = $L.fabricSpAdmin }
        @{ id = 'powerbi.noAdminConsent'; name = 'The engine identity holds NO admin-consent Power BI application permission'; kind = 'api'; required = $true; fixable = $false
           fix = ''
           manualStep = 'Microsoft Entra admin center > Enterprise applications > <engine identity> > Permissions: remove every Power BI Service application permission. Microsoft: an app that calls the read-only admin APIs as a service principal must not have admin-consent required Power BI permissions. Not removed automatically -- removing a grant is a human decision.'
           learn = $L.fabricSpAdmin }
        @{ id = 'powerbi.tenantSetting'; name = 'Fabric tenant setting "Service principals can access read-only admin APIs" is on for that group'; kind = 'api'; required = $true; fixable = $true; confirmable = 'notChecked'
           fix = 'enables the setting through the Fabric admin API (POST /v1/admin/tenantsettings/{name}/update), KEEPING every security group already listed and adding this one, then reads it back. Only possible when the caller may call Fabric admin APIs (a Fabric administrator, or a service principal an admin-API setting already allows).'
           manualStep = 'Fabric admin portal (app.fabric.microsoft.com) > Settings > Admin portal > Tenant settings > Admin API settings > "Service principals can access read-only admin APIs" > Enabled > Specific security groups > add the group > Apply. Needs a Fabric administrator. If PIM cannot read the tenant settings itself, press Confirm on this prerequisite in PIM Manager once the setting is on.'
           learn = $L.fabricSpAdmin }
        # PIM 100.142 (owner 2026-10-13: "Admin API, no membership"): the workspace roles are given through the Power BI ADMIN
        # api, whose writes need the caller to be a Fabric Administrator. OPTIONAL (required = $false) so the assignment gate
        # and the stored state of existing installs do not change; the engine's 401/403 on the admin api is its own failure
        # class (POWERBI-ADMIN-NOT-GRANTED), and the Manager shows the command where Power BI rows are staged.
        @{ id = 'powerbi.fabricAdmin'; name = 'The engine identity holds the Entra directory role Fabric Administrator'; kind = 'api'; required = $false; fixable = $true
           fix = 'OPT-IN (-GrantFabricAdministrator): assigns the directory role Fabric Administrator (looked up by name) to the engine identity as a permanent, active assignment at the directory scope through Graph, and reads it back. Never automatic -- it is standing privilege.'
           manualStep = 'A Global Administrator runs the published Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator once (browser sign-in, no PowerShell modules) -- or: Microsoft Entra admin center > Roles & admins > Fabric Administrator > Add assignments > the engine identity > Assignment type: Active, permanently assigned. Then, in the Fabric admin portal, Tenant settings > Admin API settings: "Service principals can access read-only admin APIs" and "Service principals can access admin APIs used for updates" for Specific security groups, with the group the engine identity is in.'
           learn = $L.fabricSpAdmin }
        # PIM 100.108: the CONFIRMATION of the workload (confirmation = $true). It never decides the stored state (required
        # stays $false -- the assignment gate is unchanged), but Get-PimWorkloadPrereqView counts Power BI as READY only
        # when this call answered 200 as the engine: a person's Confirm on the tenant setting does not make it ready.
        @{ id = 'powerbi.adminApi'; name = 'The engine identity gets 200 from the Power BI admin API (GET admin/groups)'; kind = 'api'; required = $false; fixable = $false; confirmation = $true
           fix = ''
           manualStep = 'Nothing to do here by itself: PIM''s own daily check calls the Power BI admin API as the engine identity, and Power BI is counted as ready only when that call answers 200. If it answers 401 or 403: the engine identity must be a member of the security group, and the Fabric tenant setting must be on for that group (the two prerequisites above). A tenant-setting change can take 15 minutes to apply; then press Check again.'
           learn = $L.fabricSpAdmin }
    ) }
    $c['AzureRbac'] = @{ workload = 'AzureRbac'; title = 'Azure RBAC (resource roles)'; checks = @(
        @{ id = 'azure.scopesKnown'; name = 'The Azure scopes PIM manages are known'; kind = 'api'; required = $true; fixable = $false
           fix = ''
           manualStep = 'The scopes are read from your PIM-Assignments-Azure-Resources rows. None yet? Pass -AzureScope /subscriptions/<id> (or a management group path) to check a scope before you delegate it.'
           learn = $L.azureRoles }
        @{ id = 'azure.uaa'; name = 'Engine identity holds User Access Administrator (or Owner) at every Azure scope PIM manages'; kind = 'api'; required = $true; fixable = $true
           fix = 'OPT-IN (-GrantAzureUserAccessAdministrator): assigns User Access Administrator at each uncovered scope through ARM and reads it back. Never automatic -- it is standing privilege (SEC-34).'
           manualStep = 'Azure portal > <scope> > Access control (IAM) > Add role assignment > User Access Administrator > Members: the engine identity -- or the published Grant-PimEnginePermissions.ps1 -AzureRoleAssignments (browser sign-in; PIM Manager shows the command). Role Based Access Control Administrator is NOT enough: PIM writes roleEligibilityScheduleRequests and roleManagementPolicies, which that role''s actions (roleAssignments write/delete only) do not include.'
           learn = $L.azureRoles }
    ) }
    $c['EntraRoles'] = @{ workload = 'EntraRoles'; title = 'Entra ID roles and PIM for Groups'; checks = @(
        @{ id = 'entra.engineRoles'; name = 'Engine identity holds the full Graph application role set (the one role map)'; kind = 'api'; required = $true; fixable = $true
           fix = 'grants each missing Microsoft Graph application role of the Engine role map (ids verified against the live Graph service principal) and reads them back'
           manualStep = 'An administrator grants it with the published Grant-PimEnginePermissions.ps1 (browser sign-in, no PowerShell modules) -- PIM Manager shows the exact command on this prerequisite and on Overview. PIM never grants itself a permission.'
           learn = $L.graphPerms }
        @{ id = 'entra.p2License'; name = 'The tenant is licensed for PIM (Microsoft Entra ID P2 service plan)'; kind = 'api'; required = $true; fixable = $false; confirmable = 'any'
           fix = ''
           manualStep = 'Microsoft 365 admin center > Billing > Licenses: Microsoft Entra ID P2 (or Microsoft Entra ID Governance). Licensed through Governance only? This check looks for the AAD_PREMIUM_P2 service plan; press Confirm on this prerequisite in PIM Manager.'
           learn = $L.pimLicense }
    ) }
    if ("$Workload".Trim()) {
        $k = @($c.Keys | Where-Object { $_ -ieq "$Workload".Trim() })
        if (-not $k.Count) { throw "Get-PimWorkloadPrereqCatalog: unknown workload '$Workload' (known: $((Get-PimWorkloadPrereqWorkloads) -join ', '))." }
        $one = [ordered]@{}; $one[$k[0]] = $c[$k[0]]; return $one
    }
    return $c
}

function Get-PimWorkloadPrereqCheckDef {
    param([Parameter(Mandatory)][string]$Id)
    foreach ($w in (Get-PimWorkloadPrereqCatalog).Values) { foreach ($d in @($w.checks)) { if ($d.id -eq $Id) { return $d } } }
    return $null
}

function Test-PimWorkloadPrereqConfirmable {
    <#
      May -ConfirmPortalStep turn this check's -Status into 'confirmed'? Only where no API can decide:
        portal checks           -> when manual / notChecked
        confirmable='notChecked'-> when the API could not be read (e.g. the caller may not read Fabric tenant settings)
        confirmable='any'       -> also a failed one (entra.p2License: a Governance-only licence has no P2 plan name)
      An API-verified failure of any other check can never be attested away.
    #>
    param([Parameter(Mandatory)][string]$Id, [string]$Status)
    $d = Get-PimWorkloadPrereqCheckDef -Id $Id
    if (-not $d) { return $false }
    $mode = if ($d.ContainsKey('confirmable')) { "$($d.confirmable)" } elseif ($d.kind -eq 'portal') { 'portal' } else { '' }
    switch ($mode) {
        'portal'     { return ($Status -in @('manual', 'notChecked')) }
        'notChecked' { return ($Status -in @('manual', 'notChecked')) }
        'any'        { return ($Status -in @('manual', 'notChecked', 'failed')) }
        default      { return $false }
    }
}

function Get-PimWorkloadPrereqTemplateMap {
    <#
      Permission-template pack id -> the workload(s) whose prerequisites it needs. The packs themselves carry NO
      prerequisite info (operator: "dont put in template"); this is the only place the link is made.
      Sentinel's pack assigns AZURE RBAC roles at the workspace (see templates\sentinel.template.json), so it needs
      the Azure RBAC prerequisites; Exchange Online has no prerequisite workload here (yet), so it maps to nothing.
    #>
    [ordered]@{
        'defender-xdr'    = @('DefenderXdr')
        'intune'          = @('Intune')
        'azure-rbac'      = @('AzureRbac')
        'entra-roles'     = @('EntraRoles')
        'entra-roles-reference' = @('EntraRoles')   # §80.4: the quick-start set of role-assignable groups -> Entra roles
        'sentinel'        = @('AzureRbac')
        'exchange-online' = @()
    }
}

function Get-PimWorkloadPrereqUngated {
    # The workloads whose prerequisites are SHOWN but never HOLD anything. Operator 2026-09-19: "we can easily enable fx
    # entra but just not all services if they have not been prepped" -- an Entra role assignment is never held.
    @('EntraRoles')
}

function Get-PimWorkloadAssignmentGate {
    <#
      REQ-W (operator 2026-09-19: "so enabling is per workload" / "but it should be possible to deploy groups" / "then last
      part is where groups are assigned in workload like defender intune"). PURE. Replaces the v2.4.379 template IMPORT
      gate: nothing is ever refused at staging and every GROUP is always created; only the workload ROLE ASSIGNMENT of
      -Workload waits for its prerequisites.
        HELD     when the workload's state in -View (Get-PimWorkloadPrereqView) is failed | incomplete | notRun |
                 unreadable (a workload missing from the view = notRun; -StoreError = the store could not be read =
                 unreadable) -- "not checked" is never green.
        NOT HELD when it is ok or STALE. A once-green workload keeps assigning after the 30-day re-check window, or
                 production assignments would silently stop 30 days after the last check; the GUI still shows the
                 stale chip amber.
        NEVER    for EntraRoles (Get-PimWorkloadPrereqUngated) and for a workload with no prerequisite definition ('').
      Returns @{ workload; held; state; reason; reasons = @(); command }. The engine (IntuneRoles, DefenderXdrRoles,
      WorkloadConnectors, AzRes -- CREATE only), /api/templates and the GUI's held note all apply this one rule.
    #>
    param([AllowEmptyString()][string]$Workload, [object[]]$View = @(), [string]$StoreError = '')
    $w = "$Workload".Trim()
    $out = [ordered]@{ workload = $w; held = $false; state = ''; reason = ''; reasons = @(); command = ''; next = '' }
    if (-not $w -or (Get-PimWorkloadPrereqUngated) -contains $w -or (Get-PimWorkloadPrereqWorkloads) -notcontains $w) { return $out }
    $v = @($View | Where-Object { $_ -and "$($_.workload)" -eq $w })[0]
    $st = if ("$StoreError".Trim()) { 'unreadable' } elseif ($v) { "$($v.state)" } else { 'notRun' }
    if (-not $st) { $st = 'notRun' }
    $out.state = $st
    # §97.1: a command only when a FIX needs one (the view decides -- Get-PimWorkloadPrereqFixCommand); otherwise the next
    # step in words (PIM checks itself / confirm the portal step). Never a script to "record" a check PIM can make itself.
    $out.command = if ($v -and "$($v.command)".Trim()) { "$($v.command)" } else { '' }
    $out.next = if ($v -and $v.PSObject.Properties['next'] -and "$($v.next)".Trim()) { "$($v.next)" } else { Get-PimWorkloadPrereqNextStep -State $st }
    if ($st -in @('ok', 'stale')) { return $out }
    # Lead decision 2026-09-19 (operator: "you decide"): AZURE is held only when the script RAN and found it not ready
    # (failed / incomplete). Never checked or unreadable is NOT a hold for Azure: v1 assigned Azure roles with no
    # prerequisite script at all, so holding an upgraded environment's new Azure assignments until someone runs a new
    # script would be a v1 -> v2 regression. Intune / Defender / Power BI keep the operator's rule (not prepped = held).
    if ($w -eq 'AzureRbac' -and $st -in @('notRun', 'unreadable')) { return $out }
    $reasons = switch ($st) {
        'failed'     { @(@($v.failed) | Where-Object { $_ } | ForEach-Object { "missing: $_" }) }
        'incomplete' { @(@($v.pending) | Where-Object { $_ } | ForEach-Object { "not confirmed: $_" }) }
        'unreadable' { @("the prerequisite status could not be read ($StoreError)") }
        default      { @('PIM has not checked this workload yet (its daily self-check, or Check again)') }
    }
    if (-not @($reasons).Count) { $reasons = @("prerequisites $st") }
    $out.held = $true
    $out.reasons = @($reasons)
    $out.reason = ("{0} prerequisites not green ({1}): {2}" -f $w, $st, (@($reasons) -join '; '))
    return $out
}

function Get-PimTemplateAssignmentGate {
    <#
      /api/templates: which workload ASSIGNMENTS of a pack would be held (Get-PimWorkloadAssignmentGate per workload the
      pack maps to). Never refuses the pack -- it only says what waits.
      Returns @{ workloads = @(ids); held = @( @{ workload; state; reason; reasons; command } ) }.
    #>
    param([Parameter(Mandatory)][string]$TemplateId, [object[]]$View = @(), [string]$StoreError = '')
    $map = Get-PimWorkloadPrereqTemplateMap
    $ws = @(); if ($map.Contains($TemplateId)) { $ws = @($map[$TemplateId]) }
    $held = New-Object System.Collections.Generic.List[object]
    foreach ($w in $ws) {
        $g = Get-PimWorkloadAssignmentGate -Workload $w -View $View -StoreError $StoreError
        if ($g.held) { $held.Add([ordered]@{ workload = $w; state = $g.state; reason = $g.reason; reasons = @($g.reasons); command = $g.command; next = $g.next }) }
    }
    return [ordered]@{ workloads = @($ws); held = @($held.ToArray()) }
}

function Get-PimWorkloadPrereqConnectorMap {
    # Workload CONNECTOR id (workloads\connectors\<id>.connector.json, the wizards' picker) -> prerequisite workload.
    [ordered]@{
        'defender-xdr' = @('DefenderXdr')
        'intune'       = @('Intune')
        'powerbi'      = @('PowerBI')
        'azure-rbac'   = @('AzureRbac')
        'entra-roles'  = @('EntraRoles')
    }
}

function Get-PimWorkloadPrereqForBinding {
    <#
      PURE. The prerequisite workload a BINDING row's assignment needs ('' = none, never held):
        PIM-Assignments-Intune -> Intune; -Defender -> DefenderXdr; -Azure-Resources -> AzureRbac;
        PIM-Assignments-Workloads -> by its Workload (a connector id; Get-PimWorkloadPrereqConnectorMap, with the
        free-text spellings a definition uses: 'Defender-XDR', 'Power BI', ...);
        PIM-Assignments-Roles-Groups / -Roles-AUs and anything else -> '' (Entra roles are never held).
    #>
    param([Parameter(Mandatory)][string]$Entity, [AllowNull()][object]$Row)
    switch ($Entity) {
        'PIM-Assignments-Intune'          { return 'Intune' }
        'PIM-Assignments-Defender'        { return 'DefenderXdr' }
        'PIM-Assignments-Azure-Resources' { return 'AzureRbac' }
        'PIM-Assignments-Workloads' {
            $wl = ''
            if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('Workload')) { $wl = "$($Row['Workload'])" } }
            elseif ($null -ne $Row -and $Row.PSObject.Properties['Workload']) { $wl = "$($Row.Workload)" }
            return (Get-PimWorkloadPrereqForConnector -Connector $wl)
        }
    }
    return ''
}

function Get-PimWorkloadPrereqForConnector {
    # PURE. A connector id / Workload spelling -> its prerequisite workload, '' when it has none.
    param([AllowEmptyString()][string]$Connector)
    $c = "$Connector".Trim().ToLowerInvariant()
    $map = Get-PimWorkloadPrereqConnectorMap
    if ($c -and $map.Contains($c)) { return "$(@($map[$c])[0])" }
    switch ($c -replace '[^a-z0-9]', '') {
        { $_ -in @('intune', 'microsoftintune', 'endpointmanager', 'mem', 'intunerbac') } { return 'Intune' }
        { $_ -in @('defender', 'defenderxdr', 'microsoftdefender', 'microsoftdefenderxdr', 'm365defender', 'microsoft365defender', 'mde', 'defenderforendpoint') } { return 'DefenderXdr' }
        'powerbi'    { return 'PowerBI' }
        'azurerbac'  { return 'AzureRbac' }
        'entraroles' { return 'EntraRoles' }
    }
    return ''
}

function Test-PimWorkloadPrereqStatusOk {
    param([string]$Status)
    return ("$Status" -in @('ok', 'fixed', 'confirmed', 'skipped'))
}

function New-PimWorkloadPrereqCheck {
    <#
      One stored check record, its static fields taken from the catalog (so a stored record can never disagree with
      the definition about what is fixable or where the portal step is). -Status is one of the vocabulary above.
    #>
    param([Parameter(Mandatory)][string]$Id,
          [Parameter(Mandatory)][ValidateSet('ok', 'fixed', 'confirmed', 'skipped', 'failed', 'manual', 'notChecked')][string]$Status,
          [string]$Detail = '',
          # §97.1: who recorded THIS check and when (a merged record mixes the engine's self-check with a person's
          # confirmations, so the record's ranBy alone no longer says who decided each check).
          [string]$By = '', [string]$CheckedUtc = '',
          # §97.1: machine-readable facts for the fix command (missingRoles = Graph roles the engine lacks;
          # missingScopes = Azure scopes without User Access Administrator; groupName = the Power BI admin-API group).
          [hashtable]$Data = @{},
          # PIM 100.108: the step for THIS tenant (the group and the identity by name and object id) in place of the
          # catalog's general one. '' = the catalog's.
          [string]$ManualStep = '')
    $d = Get-PimWorkloadPrereqCheckDef -Id $Id
    if (-not $d) { throw "New-PimWorkloadPrereqCheck: '$Id' is not in the prerequisite catalog." }
    $stepText = if ("$ManualStep".Trim()) { "$ManualStep".Trim() } else { "$($d.manualStep)" }
    $req = $true; if ($d.ContainsKey('required')) { $req = [bool]$d.required }
    $o = [ordered]@{
        id         = $Id
        name       = "$($d.name)"
        status     = $Status
        ok         = (Test-PimWorkloadPrereqStatusOk -Status $Status)
        required   = $req
        detail     = "$Detail"
        fixable    = [bool]$d.fixable
        manualStep = $(if ($Status -in @('ok', 'fixed', 'skipped')) { '' } else { $stepText })
        learn      = "$($d.learn)"
    }
    if ("$By".Trim()) { $o['by'] = "$By".Trim() }
    if ("$CheckedUtc".Trim()) { $o['checkedUtc'] = "$CheckedUtc".Trim() }
    foreach ($k in @($Data.Keys)) { if ($o.Contains("$k")) { continue }; $o["$k"] = $Data[$k] }
    return [pscustomobject]$o
}

function Get-PimWorkloadPrereqResult {
    <#
      The per-workload record the script stores: { workload; ranUtc; ranBy; ok; state; failed; pending; checks; ... }.
      state: ok | failed | incomplete (see the header). ok = (state -eq 'ok').
    #>
    param([Parameter(Mandatory)][string]$Workload, [object[]]$Checks = @(), [Parameter(Mandatory)][datetime]$RanUtc,
          [string]$RanBy = '', [string]$ToolVersion = '', [string]$TenantId = '', [string]$EngineIdentity = '',
          # §97.1: the engine's service principal object id -- the fix command (Grant-PimEnginePermissions) needs it.
          [string]$EngineObjectId = '')
    $all = @($Checks | Where-Object { $_ })
    $req = @($all | Where-Object { $_.required })
    $failed  = @($req | Where-Object { $_.status -eq 'failed' })
    $pending = @($req | Where-Object { -not $_.ok -and $_.status -ne 'failed' })
    $state = 'ok'
    if (-not $all.Count) { $state = 'incomplete' }
    elseif ($failed.Count) { $state = 'failed' }
    elseif ($pending.Count) { $state = 'incomplete' }
    return [pscustomobject][ordered]@{
        workload       = $Workload
        ranUtc         = $RanUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ranBy          = "$RanBy"
        ok             = ($state -eq 'ok')
        state          = $state
        failed         = @($failed | ForEach-Object { "$($_.name)" })
        pending        = @($pending | ForEach-Object { "$($_.name)" })
        toolVersion    = "$ToolVersion"
        tenantId       = "$TenantId"
        engineIdentity = "$EngineIdentity"
        engineObjectId = "$EngineObjectId"
        checks         = @($all)
    }
}

function Get-PimPrereqHttpCode {
    # The HTTP status from an Invoke-PimRest failure message ("GET <url> -> HTTP 403 : ..."). 0 when absent.
    param([string]$Message)
    if ("$Message" -match 'HTTP\s+(\d{3})') { return [int]$Matches[1] }
    return 0
}

function Get-PimPrereqProbeVerdict {
    <#
      Judge one GET probe made AS THE CALLER. A 403 is only evidence about the TENANT when the caller's token carries
      the permission the endpoint needs; otherwise it says nothing about the tenant and is NOT CHECKED (rule 7).
      -CallerHasPermission: $true / $false / $null (unknown -- a user token, whose rights cannot be read from it).
      Returns @{ status; detail }.
    #>
    param([int]$StatusCode, [object]$CallerHasPermission, [string]$What, [string]$Needs, [string]$ErrorText = '')
    if ($StatusCode -ge 200 -and $StatusCode -lt 300) { return @{ status = 'ok'; detail = "$What answered $StatusCode." } }
    if ($StatusCode -eq 401 -or $StatusCode -eq 403) {
        if ($CallerHasPermission -eq $true) {
            return @{ status = 'failed'; detail = "$What answered $StatusCode although the caller holds $Needs -- the feature is not active / licensed in this tenant. $ErrorText".Trim() }
        }
        $why = if ($CallerHasPermission -eq $false) { "the caller does not hold $Needs" } else { "the caller's rights cannot be read from its token (signed-in user), so a $StatusCode does not tell whether the tenant or the caller is the gap" }
        return @{ status = 'notChecked'; detail = "$What answered $StatusCode and $why. Re-run as an identity that holds $Needs. $ErrorText".Trim() }
    }
    if ($StatusCode -eq 404 -or $StatusCode -eq 400) {
        return @{ status = 'failed'; detail = "$What answered $StatusCode (the endpoint does not exist for this tenant -- the feature is off or not licensed). $ErrorText".Trim() }
    }
    if ($StatusCode -eq 0) { return @{ status = 'notChecked'; detail = "$What could not be called: $ErrorText".Trim() } }
    return @{ status = 'notChecked'; detail = "$What answered $StatusCode -- not conclusive. $ErrorText".Trim() }
}

function Test-PimPrereqTokenHasRole {
    # $true / $false when the decoded token claims show app roles; $null for a user (delegated) token.
    param([object]$Claims, [string[]]$AnyOf)
    if (-not $Claims) { return $null }
    $roles = @()
    if ($Claims.PSObject.Properties['roles']) { $roles = @($Claims.roles) }
    $isApp = ("$($Claims.idtyp)" -eq 'app') -or ($roles.Count -gt 0 -and -not $Claims.PSObject.Properties['scp'])
    if (-not $isApp) { return $null }
    foreach ($r in @($AnyOf)) { if ($roles -contains $r) { return $true } }
    return $false
}

function Test-PimPrereqGraphRoles {
    # Which of -Required the identity lacks. -Held = role VALUES it holds (names). Returns @{ ok; missing }.
    param([string[]]$Held = @(), [string[]]$Required = @())
    $h = @{}; foreach ($x in @($Held)) { if ("$x".Trim()) { $h["$x".Trim().ToLowerInvariant()] = $true } }
    $missing = @(@($Required) | Where-Object { "$_".Trim() -and -not $h.ContainsKey("$_".Trim().ToLowerInvariant()) })
    return @{ ok = ($missing.Count -eq 0); missing = $missing }
}

function Get-PimDefenderUrbacInference {
    <#
      INFERRED, never verified: no API exposes which workloads are activated for Unified RBAC (Learn: activation is a
      portal toggle; the connector probe of 2026-06-12 found no Graph endpoint). What the live roles DO show is which
      Defender permission namespaces are in use -- evidence that Unified RBAC is live, not proof a given workload is
      activated. -RoleDefinitions = beta roleManagement/defender/roleDefinitions rows (rolePermissions.allowedResourceActions).
    #>
    param([object[]]$RoleDefinitions = @())
    $labels = @{ 'secops' = 'Security operations'; 'securityposture' = 'Security posture'; 'configuration' = 'Authorization and settings' }
    $ns = New-Object System.Collections.Generic.SortedSet[string]
    $custom = 0
    foreach ($r in @($RoleDefinitions)) {
        if (-not $r) { continue }
        if ($r.PSObject.Properties['isBuiltIn'] -and -not [bool]$r.isBuiltIn) { $custom++ }
        foreach ($p in @($r.rolePermissions)) {
            foreach ($a in @($p.allowedResourceActions)) {
                $seg = @("$a".ToLowerInvariant().Split('/') | Where-Object { $_ })
                if ($seg.Count -ge 2) { [void]$ns.Add("$($seg[0])/$($seg[1])") }
            }
        }
    }
    $named = @($ns | ForEach-Object { $t = ($_ -split '/')[1]; if ($labels.ContainsKey($t)) { "$_ ($($labels[$t]))" } else { $_ } })
    $detail = if ($named.Count) { "inferred from $(@($RoleDefinitions).Count) live role(s) ($custom custom): permission namespaces in use = $($named -join ', '). This shows Unified RBAC is live; it cannot show which workloads are activated." }
              else { 'inferred: no live role carries a permission yet -- nothing to infer from.' }
    return @{ namespaces = @($ns); customRoles = $custom; detail = $detail }
}

function Test-PimAzureScopeIsWithin {
    # $true when -Scope equals -Ancestor or sits below it. '/' (tenant root) covers everything. Case-insensitive,
    # on a path boundary (/subscriptions/ab does not cover /subscriptions/abc).
    param([string]$Scope, [string]$Ancestor)
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant(); $a = "$Ancestor".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $a) { return $true }
    if ($s -eq $a) { return $true }
    return $s.StartsWith($a + '/')
}

function Test-PimAzureScopeCoverage {
    <#
      Does the engine identity hold User Access Administrator or Owner at -Scope (or above)? -Assignments = ARM
      roleAssignments rows ({ properties: { roleDefinitionId; scope } } or flat { roleDefinitionId; scope }).
      Role Based Access Control Administrator is reported but does NOT count (no roleEligibilityScheduleRequests /
      roleManagementPolicies write). Management-group ancestry (a subscription under an MG) is not resolvable from the
      ids alone, so -AncestorScopes lets the caller pass the scope's known parents.
      Returns @{ covered; by; rbacAdminOnly; detail }.
    #>
    param([Parameter(Mandatory)][string]$Scope, [object[]]$Assignments = @(), [string[]]$AncestorScopes = @())
    $ids = Get-PimWorkloadPrereqGraphRoleIds
    $good = @($ids.userAccessAdmin, $ids.owner)
    $targets = @(@($Scope) + @($AncestorScopes) | Where-Object { "$_".Trim() })
    $rbacOnly = $false
    foreach ($a in @($Assignments)) {
        if (-not $a) { continue }
        $p = if ($a.PSObject.Properties['properties'] -and $a.properties) { $a.properties } else { $a }
        $rid = ("$($p.roleDefinitionId)".Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant()
        $at = "$($p.scope)"
        $applies = $false
        foreach ($t in $targets) { if (Test-PimAzureScopeIsWithin -Scope $t -Ancestor $at) { $applies = $true; break } }
        if (-not $applies) { continue }
        if ($good -contains $rid) {
            $by = if ($rid -eq $ids.owner) { 'Owner' } else { 'User Access Administrator' }
            return @{ covered = $true; by = "$by at $(if ($at) { $at } else { '/' })"; rbacAdminOnly = $false; detail = "$Scope covered by $by at $(if ($at) { $at } else { '/' })" }
        }
        if ($rid -eq $ids.rbacAdministrator) { $rbacOnly = $true }
    }
    $d = if ($rbacOnly) { "$Scope has only Role Based Access Control Administrator -- not enough for PIM eligible assignments / policies" } else { "$Scope has no User Access Administrator / Owner for the engine identity" }
    return @{ covered = $false; by = ''; rbacAdminOnly = $rbacOnly; detail = $d }
}

function Get-PimAzureManagedScopes {
    # The distinct Azure scopes PIM manages = the AzScope of every PIM-Assignments-Azure-Resources row, plus any
    # explicit -Extra. A zero-GUID placeholder (the shipped pack's AzScope) is not a real scope and is dropped.
    param([object[]]$Rows = @(), [string[]]$Extra = @())
    $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
    foreach ($s in @(@($Rows | ForEach-Object { if ($_) { "$($_.AzScope)" } }) + @($Extra))) {
        $v = "$s".Trim().TrimEnd('/')
        if (-not $v -or $v -match '00000000-0000-0000-0000-000000000000') { continue }
        $k = $v.ToLowerInvariant()
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add($v) }
    }
    return $out.ToArray()
}

function Find-PimFabricReadOnlyAdminSetting {
    # The tenant setting behind "Service principals can access read-only admin APIs". Matched by its settingName
    # (AllowServicePrincipalsUseReadAdminAPIs) OR its title, because the Learn pages document the title and the
    # List Tenant Settings response carries both.
    param([object[]]$Settings = @())
    foreach ($s in @($Settings)) {
        if (-not $s) { continue }
        if ("$($s.settingName)" -ieq 'AllowServicePrincipalsUseReadAdminAPIs' -or "$($s.title)" -match '(?i)service principals can (access|use) read-only admin APIs') { return $s }
    }
    return $null
}

function Test-PimFabricReadOnlyAdminSetting {
    # Is the setting enabled for -GroupId (or for the whole organisation)? Returns @{ ok; found; enabled; detail }.
    param([object[]]$Settings = @(), [string]$GroupId)
    $s = Find-PimFabricReadOnlyAdminSetting -Settings $Settings
    if (-not $s) { return @{ ok = $false; found = $false; enabled = $false; detail = 'the setting "Service principals can access read-only admin APIs" is not in the tenant settings list' } }
    if (-not [bool]$s.enabled) { return @{ ok = $false; found = $true; enabled = $false; detail = "'$($s.title)' is Disabled" } }
    $groups = @($s.enabledSecurityGroups | Where-Object { $_ })
    if (-not $groups.Count) { return @{ ok = $true; found = $true; enabled = $true; detail = "'$($s.title)' is Enabled for the entire organisation" } }
    if (@($groups | Where-Object { "$($_.graphId)" -ieq "$GroupId" }).Count) {
        return @{ ok = $true; found = $true; enabled = $true; detail = "'$($s.title)' is Enabled for the group" }
    }
    return @{ ok = $false; found = $true; enabled = $true; detail = "'$($s.title)' is Enabled for $($groups.Count) other group(s) ($((@($groups | ForEach-Object { "$($_.name)" })) -join ', ')), not this one" }
}

function New-PimFabricReadOnlyAdminSettingUpdate {
    <#
      The body for POST /v1/admin/tenantsettings/{name}/update: Enabled, and the EXISTING enabled / excluded groups
      kept with -GroupId added. An update replaces the group list, so dropping the existing ones would silently take
      the setting away from whoever else relies on it -- never do that.
    #>
    param([Parameter(Mandatory)][object]$Current, [Parameter(Mandatory)][string]$GroupId, [string]$GroupName = '')
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Current.enabledSecurityGroups | Where-Object { $_ })) { $groups.Add([ordered]@{ graphId = "$($g.graphId)"; name = "$($g.name)" }) }
    if (-not @($groups | Where-Object { "$($_.graphId)" -ieq $GroupId }).Count) { $groups.Add([ordered]@{ graphId = $GroupId; name = $GroupName }) }
    $body = [ordered]@{ enabled = $true; enabledSecurityGroups = $groups.ToArray() }
    $ex = @($Current.excludedSecurityGroups | Where-Object { $_ })
    if ($ex.Count) { $body['excludedSecurityGroups'] = @($ex | ForEach-Object { [ordered]@{ graphId = "$($_.graphId)"; name = "$($_.name)" } }) }
    return $body
}

function Test-PimPowerBiAdminConsentGrants {
    # App-role assignments the engine identity holds ON the Power BI Service service principal. Any = failed.
    # -Assignments = /servicePrincipals/{id}/appRoleAssignments rows; -PowerBiSpId = the tenant's Power BI Service SP id;
    # -RoleNames maps appRoleId -> value for the message.
    param([object[]]$Assignments = @(), [string]$PowerBiSpId, [hashtable]$RoleNames = @{})
    if (-not "$PowerBiSpId".Trim()) { return @{ ok = $true; held = @(); detail = 'the Power BI Service has no service principal in this tenant, so nothing can be granted on it' } }
    $held = @(@($Assignments) | Where-Object { $_ -and "$($_.resourceId)" -ieq "$PowerBiSpId" } | ForEach-Object {
        $n = $RoleNames["$($_.appRoleId)"]; if ($n) { $n } else { "$($_.appRoleId)" } })
    if ($held.Count) { return @{ ok = $false; held = $held; detail = "holds Power BI Service application permission(s): $($held -join ', ')" } }
    return @{ ok = $true; held = @(); detail = 'no Power BI Service application permission' }
}

# --- PIM 100.108: Power BI -- WHICH identity, WHICH group, and the step that names both ---------------------------------
function Get-PimPrereqIdentityKind {
    <#
      PURE. What kind of identity a service principal is: 'application' | 'user-assigned' | 'system-assigned' |
      'managedIdentity' (a managed identity Graph did not say the kind of). Graph marks a managed identity's kind in
      alternativeNames: 'isExplicit=True' = user-assigned, 'isExplicit=False' = system-assigned. -Fallback is used when
      that mark is absent (the engine knows its own kind from PIM_ManagedIdentityClientId).
    #>
    param([object]$ServicePrincipal, [string]$Fallback = '')
    if (-not $ServicePrincipal) { return "$Fallback" }
    $type = "$(Get-PimWorkloadPrereqRecordField -Object $ServicePrincipal -Name 'servicePrincipalType')"
    if ($type -and $type -ine 'ManagedIdentity') { return 'application' }
    $alt = @(@(Get-PimWorkloadPrereqRecordField -Object $ServicePrincipal -Name 'alternativeNames') | ForEach-Object { "$_".Trim() })
    if (@($alt | Where-Object { $_ -ieq 'isExplicit=True' }).Count) { return 'user-assigned' }
    if (@($alt | Where-Object { $_ -ieq 'isExplicit=False' }).Count) { return 'system-assigned' }
    if ("$Fallback".Trim()) { return "$Fallback".Trim() }
    if ($type) { return 'managedIdentity' }
    return ''
}

function Select-PimPrereqTickJobIdentity {
    <#
      PURE. PIM 100.108 (d): WHICH identity of the hosted tick job the engine signs in as -- for Graph and for the Power
      BI call alike (engine\_shared\PIM-Rest.ps1 asks the token endpoint for the identity PIM_ManagedIdentityClientId
      names, else for the job's system-assigned one). -Job = ARM Microsoft.App/jobs/{name}.
        * the job's env PIM_ManagedIdentityClientId is set -> the USER-ASSIGNED identity with that client id;
        * else the SYSTEM-ASSIGNED identity; else, when the job has exactly one user-assigned identity, that one.
      Returns @{ objectId; clientId; identityKind; why; notUsed = @(object ids of the job's other identities) }.
      THROWS when the job names an identity it does not carry, or has none.
    #>
    param([Parameter(Mandatory)][object]$Job, [string]$JobName = 'ca-pim-tick')
    $cid = ''
    $tpl = $null
    if ($Job.PSObject.Properties['properties'] -and $Job.properties -and $Job.properties.PSObject.Properties['template']) { $tpl = $Job.properties.template }
    if ($tpl) {
        foreach ($c in @($tpl.containers)) {
            if (-not $c) { continue }
            foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -eq 'PIM_ManagedIdentityClientId' -and "$($e.value)".Trim()) { $cid = "$($e.value)".Trim().ToLowerInvariant() } }
        }
    }
    $idn = $null; if ($Job.PSObject.Properties['identity']) { $idn = $Job.identity }
    $sys = ''; if ($idn -and $idn.PSObject.Properties['principalId']) { $sys = "$($idn.principalId)".Trim().ToLowerInvariant() }
    $ua = New-Object System.Collections.Generic.List[object]
    if ($idn -and $idn.PSObject.Properties['userAssignedIdentities'] -and $idn.userAssignedIdentities) {
        foreach ($p in $idn.userAssignedIdentities.PSObject.Properties) {
            $ua.Add(@{ resourceId = "$($p.Name)"; objectId = "$($p.Value.principalId)".Trim().ToLowerInvariant(); clientId = "$($p.Value.clientId)".Trim().ToLowerInvariant() })
        }
    }
    $pick = $null
    if ($cid) {
        $hit = @($ua | Where-Object { $_.clientId -eq $cid })[0]
        if (-not $hit -or -not $hit.objectId) { throw "the tick job '$JobName' names the user-assigned identity with client id $cid (PIM_ManagedIdentityClientId), but that identity is not attached to the job." }
        $pick = @{ objectId = $hit.objectId; clientId = $cid; identityKind = 'user-assigned'; why = "the tick job's PIM_ManagedIdentityClientId names it" }
    } elseif ($sys) {
        $pick = @{ objectId = $sys; clientId = ''; identityKind = 'system-assigned'; why = 'the tick job names no user-assigned identity, so it signs in as its system-assigned one' }
    } elseif ($ua.Count -eq 1 -and $ua[0].objectId) {
        $pick = @{ objectId = $ua[0].objectId; clientId = $ua[0].clientId; identityKind = 'user-assigned'; why = 'it is the only identity the tick job has' }
    } else {
        throw "the tick job '$JobName' has no identity the engine can sign in as -- run the hosting step first."
    }
    $others = @(@(@($sys) + @($ua | ForEach-Object { $_.objectId })) | Where-Object { $_ -and $_ -ne $pick.objectId } | Select-Object -Unique)
    $pick['notUsed'] = @($others)
    return $pick
}

function Get-PimPowerBiPrereqIdentityText {
    # PURE. The engine identity as a person must find it: "<name> (object id <id>, <kind>)".
    param([object]$Identity)
    $name = "$(Get-PimWorkloadPrereqRecordField -Object $Identity -Name 'displayName')".Trim(); if (-not $name) { $name = 'the engine identity' }
    $oid = "$(Get-PimWorkloadPrereqRecordField -Object $Identity -Name 'objectId')".Trim()
    $k = "$(Get-PimWorkloadPrereqRecordField -Object $Identity -Name 'identityKind')".Trim()
    if (-not $k) { $k = "$(Get-PimWorkloadPrereqRecordField -Object $Identity -Name 'kind')".Trim() }
    $kind = switch ($k) {
        'user-assigned'   { 'user-assigned managed identity' }
        'system-assigned' { 'system-assigned managed identity' }
        'managedIdentity' { 'managed identity' }
        'application'     { 'application' }
        default           { '' }
    }
    $in = New-Object System.Collections.Generic.List[string]
    if ($oid) { $in.Add("object id $oid") }
    if ($kind) { $in.Add("$kind") }
    if ($in.Count) { return "$name ($($in -join ', '))" }
    return $name
}

function Get-PimPowerBiPrereqSteps {
    <#
      PURE. PIM 100.108 (a): the steps of the three Power BI prerequisites for THIS tenant -- the security group by name
      (and object id once it exists) and the ONE identity that must be in it, by name, object id and kind. "Add the
      group" without saying which group, or which member, is what this replaces.
      Returns @{ group; groupMember; tenantSetting; addYourself (the exact manual step after a refusal); who; groupText }.
    #>
    param([string]$GroupName = '', [string]$GroupId = '', [object]$Identity = $null)
    $g = "$GroupName".Trim(); if (-not $g) { $g = 'grp-pim-powerbi-admin-api' }
    $gid = "$GroupId".Trim()
    $gq = "'$g'"; if ($gid) { $gq = "'$g' (object id $gid)" }
    $who = Get-PimPowerBiPrereqIdentityText -Identity $Identity
    $oid = "$(Get-PimWorkloadPrereqRecordField -Object $Identity -Name 'objectId')".Trim()
    $find = if ($oid) { "search for the object id $oid" } else { 'search for the engine identity' }
    return @{
        who = $who; groupText = $gq
        group = "Microsoft Entra admin center > Groups > New group > Group type: Security > Group name: $g > Members: $who > Create. This is the only member the group needs: it is the identity PIM uses for the Power BI call."
        groupMember = "Microsoft Entra admin center > Groups > $gq > Members > Add members > $find > select $who > Select. This is the only member the group needs: it is the identity PIM uses for the Power BI call."
        tenantSetting = "Fabric admin portal (app.fabric.microsoft.com) > Settings > Admin portal > Tenant settings > Admin API settings > ""Service principals can access read-only admin APIs"" > Enabled > Specific security groups > add the group $gq > Apply. The group must contain $who. Needs a Fabric administrator. If PIM cannot read the tenant settings itself, press Confirm on this prerequisite in PIM Manager once the setting is on."
        addYourself = "Add these members to this group yourself: group $gq <- $who."
    }
}

# --- PIM 100.142: Power BI through the ADMIN api -- the one Fabric instruction and the notice the Manager shows ---------
function Get-PimFabricAdminApiInstruction {
    <#
      PURE. The ONE plain instruction for the Fabric tenant settings the admin api needs (the exact admin-portal names, from
      the owner's tenant 2026-10-13). PIM never switches these itself: the read-only setting is set by the prerequisites
      script where it may, the "used for updates" one is a person's decision in the portal.
    #>
    param([string]$GroupName = '')
    $g = "$GroupName".Trim(); if (-not $g) { $g = 'grp-pim-powerbi-admin-api' }
    return ("In the Fabric admin portal (app.fabric.microsoft.com) > Settings > Admin portal > Tenant settings > Admin API settings, set ""Service principals can access read-only admin APIs"" and ""Service principals can access admin APIs used for updates"" to Enabled for Specific security groups, with the same group for both: '{0}' (PIM Manager's identity is in it). Check also that Developer settings > ""Service principals can call Fabric public APIs"" is enabled. A change can take about 15 minutes to apply." -f $g)
}

function Get-PimPowerBiAdminGrantCommand {
    # PURE. The two lines (download + run) a Global Administrator runs once: the published prerequisites script for Power BI
    # with -GrantFabricAdministrator. Browser sign-in; no identity on the command line (framework rule 3).
    param([hashtable]$Env = @{})
    return ((Get-PimWorkloadPrereqCommand -Workload 'PowerBI' -Env $Env) + ' -GrantFabricAdministrator')
}

function Get-PimPowerBiAdminNotice {
    <#
      PURE. PIM 100.142 (4): what the Manager shows where a Power BI workload row or a discovered workspace is staged. show =
      $true ONLY when the engine's currently failing items (Get-PimEngineItemFailures) hold at least one
      POWERBI-ADMIN-NOT-GRANTED; then one calm line, the two-line command for THIS install and the Fabric instruction.
      -Env: tenantId (+ subscriptionId / resourceGroup / tickJobName); -EngineObjectId from the stored Power BI record.
    #>
    param([AllowNull()][object[]]$Failures = @(), [hashtable]$Env = @{}, [string]$EngineObjectId = '', [string]$GroupName = '')
    $hit = @(@($Failures) | Where-Object { $_ -and "$($_.code)" -eq 'POWERBI-ADMIN-NOT-GRANTED' })
    $out = [ordered]@{ show = [bool]$hit.Count; failureClass = 'POWERBI-ADMIN-NOT-GRANTED'; items = $hit.Count; line = ''; command = ''; fabric = '' }
    if (-not $hit.Count) { return $out }
    $e = @{}; foreach ($k in @($Env.Keys)) { $e[$k] = $Env[$k] }
    if ("$EngineObjectId".Trim() -and -not "$($e['engineObjectId'])".Trim()) { $e['engineObjectId'] = "$EngineObjectId".Trim() }
    $out.line = 'PIM Manager cannot reach Power BI yet, so Power BI workspace roles are not given. A Global Administrator runs these two lines once:'
    $out.command = Get-PimPowerBiAdminGrantCommand -Env $e
    $out.fabric = Get-PimFabricAdminApiInstruction -GroupName $GroupName
    return $out
}

function Get-PimPowerBiPrereqFacts {
    <#
      PURE. What a stored Power BI record says about the group and the identity (for the view: a record written before
      100.108, or a check re-created by Confirm / Withdraw, carries only the general step).
      Returns @{ groupName; groupId; identity = @{ displayName; objectId; identityKind } }.
    #>
    param([object]$Record)
    $gn = ''; $gid = ''; $idn = $null
    foreach ($c in @(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'checks')) {
        if (-not $c -or "$($c.id)" -notin @('powerbi.group', 'powerbi.groupMember')) { continue }
        $x = "$(Get-PimWorkloadPrereqRecordField -Object $c -Name 'groupName')".Trim(); if ($x -and -not $gn) { $gn = $x }
        $x = "$(Get-PimWorkloadPrereqRecordField -Object $c -Name 'groupId')".Trim(); if ($x -and -not $gid) { $gid = $x }
        if ("$($c.id)" -eq 'powerbi.group' -and "$($c.detail)" -match "^(created )?'([^']+)' \(([0-9a-fA-F-]{36})\)") { if (-not $gn) { $gn = $Matches[2] }; if (-not $gid) { $gid = $Matches[3] } }
        $m = @(Get-PimWorkloadPrereqRecordField -Object $c -Name 'members' | Where-Object { $_ })[0]
        if ($m -and -not $idn) { $idn = @{ displayName = "$(Get-PimWorkloadPrereqRecordField -Object $m -Name 'displayName')"; objectId = "$(Get-PimWorkloadPrereqRecordField -Object $m -Name 'objectId')"; identityKind = "$(Get-PimWorkloadPrereqRecordField -Object $m -Name 'identityKind')" } }
    }
    if (-not $idn) {
        $oid = "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'engineObjectId')".Trim(); $name = ''
        $ei = "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'engineIdentity')"
        if ($ei -match '^(.*?)\s*\(([0-9a-fA-F-]{36})\)\s*$') { $name = $Matches[1].Trim(); if (-not $oid) { $oid = $Matches[2] } }
        $idn = @{ displayName = $name; objectId = $oid; identityKind = '' }
    }
    return @{ groupName = $gn; groupId = $gid; identity = $idn }
}

function Merge-PimWorkloadPrereqsSetting {
    # The stored pim.Settings 'WorkloadPrereqs' with this run's workload REPLACED and every other workload kept.
    param([object]$Current, [Parameter(Mandatory)][object]$Result)
    $h = [ordered]@{}
    if ($Current) {
        if ($Current -is [System.Collections.IDictionary]) { foreach ($k in $Current.Keys) { $h["$k"] = $Current[$k] } }
        else { foreach ($p in $Current.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    }
    $h["$($Result.workload)"] = $Result
    return $h
}

function ConvertFrom-PimTickJobId {
    # '/subscriptions/<s>/resourceGroups/<rg>/providers/Microsoft.App/jobs/<name>' -> @{ subscriptionId; resourceGroup; jobName }.
    param([string]$Id)
    if ("$Id".Trim() -match '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.App/jobs/([^/]+)$') {
        return @{ subscriptionId = $Matches[1]; resourceGroup = $Matches[2]; jobName = $Matches[3] }
    }
    return $null
}

# --- §97.1: the published scripts a FIX points at (framework rule 3: no modules, browser sign-in) -----------------------
function Get-PimWorkloadPrereqSupportScriptUrl {
    # The published, standalone copy of a support script (tools\setup\Build-PimSupportScripts.ps1 -> invardia.com).
    param([Parameter(Mandatory)][string]$Script)
    return (Get-PimSupportScriptUrl -Script $Script)
}

function Get-PimWorkloadPrereqDownload {
    # The download + run lines (tools\setup\_PimScriptDoc.ps1, owner 2026-10-11) ending in '.\<file>', so a caller appends the
    # parameters to the run line. Lines are joined with a newline: a person pastes the block into PowerShell.
    param([Parameter(Mandatory)][string]$Script)
    return ((Get-PimSupportScriptCommand -Script $Script) -join "`n")
}

function Get-PimWorkloadPrereqCommand {
    <#
      §97.1 (owner 2026-10-08: "we dont support certificates"). The command a person runs to FIX one workload's
      prerequisites that PIM cannot fix itself (create the Power BI admin-API group and add the engine, switch the Fabric
      tenant setting, enable Sentinel on a dedicated workspace): the PUBLISHED Initialize-PimWorkloadPrereqs.ps1, browser
      sign-in, no PowerShell modules. NEVER an identity on the command line -- no certificate, no client id, no secret:
      the person signs in in the browser. Anything the Manager does not know is a <placeholder>.
      Recording the result is not this command's job: PIM's own self-check (job workload-prereqs) records it -- the person
      presses Check again afterwards.
    #>
    param([Parameter(Mandatory)][string]$Workload, [hashtable]$Env = @{})
    $v = { param($k, $ph) $x = "$($Env[$k])".Trim(); if ($x) { $x } else { $ph } }
    $parts = @((Get-PimWorkloadPrereqDownload -Script 'Initialize-PimWorkloadPrereqs.ps1'), "-Workload $Workload",
               "-TenantId $(& $v 'tenantId' '<tenant-id>')")
    $oid = "$($Env['engineObjectId'])".Trim()
    if ($oid) { $parts += "-EngineObjectId $oid" }
    if (-not $oid -or $Workload -in @('DefenderXdr', 'AzureRbac')) {
        # Without the engine's object id the script finds it from the hosted tick job; Defender (the dedicated Sentinel
        # workspace) and Azure (the scopes) also need the hosting subscription + resource group.
        $parts += "-SubscriptionId $(& $v 'subscriptionId' '<hosting-subscription-id>')"
        $parts += "-ResourceGroup $(& $v 'resourceGroup' '<resource-group>')"
        $tj = "$($Env['tickJobName'])".Trim()
        if ($tj -and $tj -ne 'ca-pim-tick') { $parts += "-TickJobName $tj" }
    }
    return ($parts -join ' ')
}

function Get-PimWorkloadPrereqGrantCommand {
    <#
      §97.1. The published Grant-PimEnginePermissions.ps1 one-liner (browser sign-in, no modules -- the same script
      Overview > Verify permissions shows) for the Graph application roles and Azure role assignments the engine lacks.
      '' when there is nothing to grant.
    #>
    param([string]$TenantId, [string]$EngineObjectId, [string[]]$GraphPermissions = @(), [string[]]$AzureScopes = @())
    $roles = @(@($GraphPermissions) | ForEach-Object { "$_" -replace '[^A-Za-z0-9._-]', '' } | Where-Object { $_ } | Select-Object -Unique)
    $scopes = @(@($AzureScopes) | ForEach-Object { "$_".Trim() -replace "'", '' } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $roles.Count -and -not $scopes.Count) { return '' }
    $tid = "$TenantId".Trim(); if (-not $tid) { $tid = '<tenant-id>' }
    $oid = "$EngineObjectId".Trim(); if (-not $oid) { $oid = '<engine-object-id>' }
    $c = (Get-PimWorkloadPrereqDownload -Script 'Grant-PimEnginePermissions.ps1') + " -TenantId '$tid' -EngineObjectId '$oid'"
    if ($roles.Count) { $c += ' -GraphPermissions ' + (@($roles | ForEach-Object { "'$_'" }) -join ',') }
    if ($scopes.Count) { $c += ' -AzureRoleAssignments ' + (@($scopes | ForEach-Object { "'User Access Administrator@$_'" }) -join ',') }
    return $c
}

function Get-PimWorkloadPrereqRecordField {
    # A field of a stored record / check that may be a hashtable or a parsed JSON object. $null when absent.
    param([object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $null
}

function Get-PimWorkloadPrereqFixCommand {
    <#
      PURE. §97.1 -- the ONE command the page shows for a workload that is not green, decided from what the record
      says is missing:
        * engine Graph roles missing (defender / intune / entra engine-role checks FAILED) and/or User Access
          Administrator missing at Azure scopes (azure.uaa FAILED)  -> Grant-PimEnginePermissions.ps1 (published)
        * something only a person can create (Power BI group / membership / Fabric tenant setting, Sentinel on a
          workspace)                                                -> Initialize-PimWorkloadPrereqs.ps1 (published)
        * only portal steps / checks PIM could not read / a failure only a portal step fixes (Unified RBAC activation,
          the licence)                                              -> '' (the page shows the step, and Confirm)
        * an engine-role failure whose roles are not recorded       -> Initialize-PimWorkloadPrereqs.ps1 (it says what)
      Both scripts sign in in the browser; neither command ever carries a certificate or any credential.
    #>
    param([Parameter(Mandatory)][string]$Workload, [object]$Record, [hashtable]$Env = @{})
    if (-not $Record) { return '' }
    $st = "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'state')"
    if ($st -eq 'ok') { return '' }
    $e = @{}; foreach ($k in @($Env.Keys)) { $e[$k] = $Env[$k] }
    $oid = "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'engineObjectId')".Trim()
    if (-not $oid -and "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'engineIdentity')" -match '\(([0-9a-fA-F-]{36})\)\s*$') { $oid = $Matches[1] }
    if ($oid -and -not "$($e['engineObjectId'])".Trim()) { $e['engineObjectId'] = $oid }
    $tid = "$($e['tenantId'])".Trim(); if (-not $tid) { $tid = "$(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'tenantId')".Trim(); if ($tid) { $e['tenantId'] = $tid } }
    $single = @{ 'defender.engineRole' = 'RoleManagement.ReadWrite.Defender'; 'intune.engineRole' = 'DeviceManagementRBAC.ReadWrite.All' }
    $roles = New-Object System.Collections.Generic.List[string]; $scopes = New-Object System.Collections.Generic.List[string]
    $needScript = $false; $unknownFailure = $false
    foreach ($c in @(Get-PimWorkloadPrereqRecordField -Object $Record -Name 'checks')) {
        if (-not $c) { continue }
        $id = "$($c.id)"; $s = "$($c.status)"
        if ([bool]$c.ok -or $s -in @('ok', 'fixed', 'confirmed', 'skipped')) { continue }
        $req = $true; if ($c.PSObject.Properties['required']) { $req = [bool]$c.required }
        if (-not $req) { continue }
        switch -Regex ($id) {
            '^(defender\.engineRole|intune\.engineRole|entra\.engineRoles)$' {
                if ($s -ne 'failed') { break }
                $m = @(Get-PimWorkloadPrereqRecordField -Object $c -Name 'missingRoles' | Where-Object { "$_".Trim() })
                if (-not $m.Count -and $single.ContainsKey($id)) { $m = @($single[$id]) }
                if (-not $m.Count -and "$($c.detail)" -match 'missing: ([A-Za-z0-9., -]+?)(\s\(|\s--|$)') { $m = @($Matches[1] -split '\s*,\s*' | Where-Object { $_ -match '^[A-Za-z][A-Za-z0-9.-]+\.[A-Za-z0-9.-]+$' }) }
                if ($m.Count) { foreach ($r in $m) { if (-not $roles.Contains("$r")) { $roles.Add("$r") } } } else { $unknownFailure = $true }
                break
            }
            '^azure\.uaa$' {
                if ($s -ne 'failed') { break }
                $m = @(Get-PimWorkloadPrereqRecordField -Object $c -Name 'missingScopes' | Where-Object { "$_".Trim() })
                if ($m.Count) { foreach ($x in $m) { if (-not $scopes.Contains("$x")) { $scopes.Add("$x") } } } else { $unknownFailure = $true }
                break
            }
            '^powerbi\.(group|groupMember)$' { if ($s -eq 'failed') { $needScript = $true }; break }
            '^powerbi\.tenantSetting$'      { if ($s -eq 'failed') { $needScript = $true }; break }
            '^defender\.sentinelEnabled$'   { if ($s -eq 'failed') { $needScript = $true }; break }
            default {
                # A failure the script can fix (the catalog says fixable) -> the script; one only a portal step fixes
                # (Unified RBAC activation, a licence, a Power BI permission to remove) -> no command: the page shows
                # the check's own "To do", and Confirm where nothing can verify it.
                $def = Get-PimWorkloadPrereqCheckDef -Id $id
                if ($s -eq 'failed' -and $def -and [bool]$def.fixable) { $needScript = $true }
            }
        }
    }
    $cmds = New-Object System.Collections.Generic.List[string]
    $g = Get-PimWorkloadPrereqGrantCommand -TenantId "$($e['tenantId'])" -EngineObjectId "$($e['engineObjectId'])" -GraphPermissions @($roles) -AzureScopes @($scopes)
    if ($g) { $cmds.Add($g) }
    if ($needScript -or ($unknownFailure -and -not $cmds.Count)) { $cmds.Add((Get-PimWorkloadPrereqCommand -Workload $Workload -Env $e)) }
    return (@($cmds) -join "`n")   # each command is the two-line download + run block
}

function Get-PimWorkloadPrereqNextStep {
    # PURE. The next step in words for one workload state (§97.1 -- PIM checks itself; a person only fixes or confirms).
    param([string]$State, [string]$Command = '', [int]$Confirmable = 0)
    switch ("$State") {
        'ok'         { return '' }
        'notRun'     { return 'Not checked yet. PIM checks this itself every day (job workload-prereqs) -- press Check again to check now.' }
        'stale'      { return 'The last check is older than the re-check window. PIM re-checks it every day -- press Check again to check now.' }
        'unreadable' { return 'The prerequisite status could not be read from the store.' }
    }
    $p = New-Object System.Collections.Generic.List[string]
    if ("$Command".Trim()) { $p.Add('Run the command below once as an administrator (it signs you in in the browser; no PowerShell modules), then press Check again.') }
    if ($Confirmable -gt 0) { $p.Add('Do the portal step(s) listed, then press Confirm on each.') }
    if (-not $p.Count) { $p.Add('See each check below: fix what it names, then press Check again.') }
    return ($p -join ' ')
}

function ConvertTo-PimWorkloadPrereqUtcText {
    # A stored date -> 'yyyy-MM-ddTHH:mm:ssZ' ('' when unreadable). pwsh 7's ConvertFrom-Json hands a [datetime].
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return $d.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    $p = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$p)) { return $p.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return ''
}

function Get-PimWorkloadPrereqStoredRecord {
    # The stored record of one workload from pim.Settings 'WorkloadPrereqs' (hashtable or parsed JSON). $null when absent.
    param([object]$Stored, [Parameter(Mandatory)][string]$Workload)
    if (-not $Stored) { return $null }
    if ($Stored -is [System.Collections.IDictionary]) { if ($Stored.Contains($Workload)) { return $Stored[$Workload] }; return $null }
    if ($Stored.PSObject.Properties[$Workload]) { return $Stored.$Workload }
    return $null
}

function Copy-PimWorkloadPrereqCheck {
    # A stored check as a fresh [pscustomobject] (every property kept), with -Set fields overwritten.
    param([Parameter(Mandatory)][object]$Check, [hashtable]$Set = @{})
    $o = [ordered]@{}
    if ($Check -is [System.Collections.IDictionary]) { foreach ($k in $Check.Keys) { $o["$k"] = $Check[$k] } }
    else { foreach ($p in $Check.PSObject.Properties) { $o[$p.Name] = $p.Value } }
    foreach ($k in @($Set.Keys)) { $o["$k"] = $Set[$k] }
    return [pscustomobject]$o
}

function Merge-PimWorkloadPrereqRecord {
    <#
      PURE. §97.1 -- one workload's NEW result (-Fresh, from Get-PimWorkloadPrereqResult: the engine's self-check or a
      person's script run) merged onto what was stored (-Stored, $null = nothing), check by check:
        * a stored CONFIRMED check is kept while the new result could still be confirmed (Test-PimWorkloadPrereqConfirmable)
          and is not itself verified ok -- a portal confirmation survives every daily self-check;
        * a stored SKIPPED Data Operations check is kept (a person said Data Operations roles are not used);
        * a new result that could not decide (notChecked / manual) keeps a stored DECIDED one (ok / fixed / failed) --
          e.g. a Fabric administrator verified the tenant setting that the engine cannot read itself;
        * everything else: the new result wins (an API-verified answer replaces an older one).
      A kept check says so (kept = $true) and keeps who recorded it and when (by / checkedUtc). The state is recomputed.
      Returns the merged record (same shape as Get-PimWorkloadPrereqResult).
    #>
    param([object]$Stored, [Parameter(Mandatory)][object]$Fresh)
    $wl = "$($Fresh.workload)"
    $storedChecks = @{}
    $sBy = "$(Get-PimWorkloadPrereqRecordField -Object $Stored -Name 'ranBy')"
    $sAt = ConvertTo-PimWorkloadPrereqUtcText -Value (Get-PimWorkloadPrereqRecordField -Object $Stored -Name 'ranUtc')
    foreach ($c in @(Get-PimWorkloadPrereqRecordField -Object $Stored -Name 'checks')) { if ($c -and "$($c.id)") { $storedChecks["$($c.id)"] = $c } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Fresh.checks)) {
        if (-not $c) { continue }
        $s = $storedChecks["$($c.id)"]
        $keep = $false
        if ($s -and -not [bool]$c.ok) {
            $ss = "$($s.status)"; $def = Get-PimWorkloadPrereqCheckDef -Id "$($c.id)"
            if ($ss -eq 'confirmed' -and (Test-PimWorkloadPrereqConfirmable -Id "$($c.id)" -Status "$($c.status)")) { $keep = $true }
            elseif ($ss -eq 'skipped' -and $def -and $def.ContainsKey('dataOperations') -and $def.dataOperations) { $keep = $true }
            elseif ("$($c.status)" -in @('notChecked', 'manual') -and $ss -in @('ok', 'fixed', 'failed')) { $keep = $true }
        }
        if ($keep) {
            $set = @{ kept = $true }
            if (-not (Get-PimWorkloadPrereqRecordField -Object $s -Name 'by') -and $sBy) { $set['by'] = $sBy }
            if (-not (Get-PimWorkloadPrereqRecordField -Object $s -Name 'checkedUtc') -and $sAt) { $set['checkedUtc'] = $sAt }
            $set['latest'] = "$($c.status): $($c.detail)".Trim()
            $out.Add((Copy-PimWorkloadPrereqCheck -Check $s -Set $set))
        } else { $out.Add($c) }
    }
    $ran = [datetime]::UtcNow
    $p = ConvertTo-PimWorkloadPrereqUtcText -Value $Fresh.ranUtc
    if ($p) { $ran = [datetime]::Parse($p, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') }
    $oid = "$($Fresh.engineObjectId)"; if (-not $oid) { $oid = "$(Get-PimWorkloadPrereqRecordField -Object $Stored -Name 'engineObjectId')" }
    return (Get-PimWorkloadPrereqResult -Workload $wl -Checks @($out.ToArray()) -RanUtc $ran -RanBy "$($Fresh.ranBy)" -ToolVersion "$($Fresh.toolVersion)" `
              -TenantId "$($Fresh.tenantId)" -EngineIdentity "$($Fresh.engineIdentity)" -EngineObjectId $oid)
}

function Set-PimWorkloadPrereqAttestation {
    <#
      PURE. §97.1 -- the Manager's Confirm / Not used / Withdraw on ONE check (Admin+, audited by the caller), recorded
      exactly like -ConfirmPortalStep: 'confirmed' = attested, not API-verified, and says who and when.
        confirm   -- only where Test-PimWorkloadPrereqConfirmable allows it (a portal step, a check PIM could not read,
                     the P2 licence). An API-verified failure can never be confirmed away.
        skip      -- a Data Operations check: "Data Operations roles are not used" (recorded 'skipped', like
                     -SkipDataOperations).
        withdraw  -- undo a confirmation / skip: back to 'manual' (portal step) or 'notChecked'; the next self-check decides.
      -Stored = the whole pim.Settings 'WorkloadPrereqs' value. Returns @{ ok; code (HTTP); error; value (the whole new
      setting); before; after } -- nothing is written here.
    #>
    param([object]$Stored, [Parameter(Mandatory)][string]$Workload, [Parameter(Mandatory)][string]$CheckId,
          [Parameter(Mandatory)][ValidateSet('confirm', 'skip', 'withdraw')][string]$Action, [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [ordered]@{ ok = $false; code = 400; error = ''; value = $null; before = $null; after = $null }
    if ((Get-PimWorkloadPrereqWorkloads) -notcontains $Workload) { $res.error = "unknown workload '$Workload'"; return $res }
    $def = Get-PimWorkloadPrereqCheckDef -Id $CheckId
    if (-not $def -or -not @((Get-PimWorkloadPrereqCatalog -Workload $Workload)[$Workload].checks | Where-Object { $_.id -eq $CheckId }).Count) { $res.error = "'$CheckId' is not a check of $Workload"; return $res }
    $rec = Get-PimWorkloadPrereqStoredRecord -Stored $Stored -Workload $Workload
    if (-not $rec) { $res.code = 409; $res.error = "PIM has not checked $Workload yet -- press Check again first, then confirm what it cannot check itself."; return $res }
    $checks = @(Get-PimWorkloadPrereqRecordField -Object $rec -Name 'checks' | Where-Object { $_ })
    $cur = @($checks | Where-Object { "$($_.id)" -eq $CheckId })[0]
    $curStatus = if ($cur) { "$($cur.status)" } else { 'notChecked' }
    $who = if ("$By".Trim()) { "$By".Trim() } else { 'an administrator' }
    $at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $new = $null
    switch ($Action) {
        'confirm' {
            if ($curStatus -eq 'confirmed') { $res.code = 409; $res.error = 'already confirmed'; return $res }
            if (-not (Test-PimWorkloadPrereqConfirmable -Id $CheckId -Status $curStatus)) {
                $res.code = 409
                $res.error = $(if ([bool]$cur.ok) { "'$($def.name)' is already verified ($curStatus) -- nothing to confirm." } else { "'$($def.name)' was verified through an API as $curStatus -- it cannot be confirmed away. Fix it, then press Check again." })
                return $res
            }
            $new = New-PimWorkloadPrereqCheck -Id $CheckId -Status 'confirmed' -By $who -CheckedUtc $at -Detail ("confirmed in PIM Manager by {0} at {1} (attested, not API-verified). Before: {2}" -f $who, $at, "$($cur.detail)".Trim())
        }
        'skip' {
            if (-not ($def.ContainsKey('dataOperations') -and $def.dataOperations)) { $res.code = 409; $res.error = "'$($def.name)' cannot be marked as not used -- only the Data Operations checks can."; return $res }
            if ($curStatus -eq 'skipped') { $res.code = 409; $res.error = 'already marked as not used'; return $res }
            $new = New-PimWorkloadPrereqCheck -Id $CheckId -Status 'skipped' -By $who -CheckedUtc $at -Detail ("marked as not used in PIM Manager by {0} at {1}: no Data Operations role is delegated." -f $who, $at)
        }
        'withdraw' {
            if ($curStatus -notin @('confirmed', 'skipped')) { $res.code = 409; $res.error = "'$($def.name)' is $curStatus -- there is no confirmation to withdraw."; return $res }
            $back = if ($def.kind -eq 'portal') { 'manual' } else { 'notChecked' }
            $new = New-PimWorkloadPrereqCheck -Id $CheckId -Status $back -By $who -CheckedUtc $at -Detail ("the confirmation was withdrawn in PIM Manager by {0} at {1}; PIM checks it again at its next self-check." -f $who, $at)
        }
    }
    $list = New-Object System.Collections.Generic.List[object]; $done = $false
    foreach ($c in $checks) { if ("$($c.id)" -eq $CheckId) { $list.Add($new); $done = $true } else { $list.Add($c) } }
    if (-not $done) { $list.Add($new) }
    $ranText = ConvertTo-PimWorkloadPrereqUtcText -Value (Get-PimWorkloadPrereqRecordField -Object $rec -Name 'ranUtc')
    $ran = if ($ranText) { [datetime]::Parse($ranText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } else { $NowUtc }
    $f = { param($n) "$(Get-PimWorkloadPrereqRecordField -Object $rec -Name $n)" }
    $newRec = Get-PimWorkloadPrereqResult -Workload $Workload -Checks @($list.ToArray()) -RanUtc $ran -RanBy (& $f 'ranBy') -ToolVersion (& $f 'toolVersion') `
                -TenantId (& $f 'tenantId') -EngineIdentity (& $f 'engineIdentity') -EngineObjectId (& $f 'engineObjectId')
    $res.before = [ordered]@{ check = $CheckId; status = $curStatus; state = (& $f 'state') }
    $res.after = [ordered]@{ check = $CheckId; status = "$($new.status)"; state = "$($newRec.state)"; by = $who }
    $res.value = Merge-PimWorkloadPrereqsSetting -Current $Stored -Result $newRec
    $res.ok = $true; $res.code = 200
    return $res
}

function Get-PimWorkloadPrereqView {
    <#
      What the Manager shows (GET /api/workload-prereqs): per workload the stored result judged against NOW.
        state: ok | failed | incomplete | stale (older than -StaleDays) | notRun
        chip : green (ok) | red (failed) | amber (everything else -- "not checked" is never green)
      §97.1: command = the FIX command only (Get-PimWorkloadPrereqFixCommand; '' when PIM can check / the person can
      confirm it in the page), next = the next step in words, and per check what the page may offer: canConfirm
      (Confirm), canSkip (Not used), canWithdraw (Withdraw). selfChecked = the record came from PIM's own self-check.
      -Stored = pim.Settings 'WorkloadPrereqs' (parsed) or $null; -Env feeds the command.
    #>
    param([object]$Stored, [hashtable]$Env = @{}, [Parameter(Mandatory)][datetime]$NowUtc, [int]$StaleDays = 30)
    $cat = Get-PimWorkloadPrereqCatalog
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($w in (Get-PimWorkloadPrereqWorkloads)) {
        $r = Get-PimWorkloadPrereqStoredRecord -Stored $Stored -Workload $w
        # PIM 100.108 (e): ready = what the page COUNTS ("N of M workloads ready"). state ok, AND -- for a workload with a
        # confirmation call (Power BI: the engine gets 200 from the admin API) -- that call answered 200. A person's Confirm
        # on the tenant setting makes the STATE ok; it never makes the workload ready by itself. notReady says why;
        # confirmation = @{ id; status; ok; detail } ($null for a workload without one). The state -- and with it the
        # assignment gate -- is unchanged.
        $v = [ordered]@{ workload = $w; title = $cat[$w].title; command = ''; next = ''; state = 'notRun'; chip = 'amber'; ranUtc = ''; ranBy = ''; selfChecked = $false
                         ageDays = $null; failed = @(); pending = @(); checks = @(); engineObjectId = ''; ready = $false; notReady = ''; confirmation = $null }
        if ($r) {
            # 🪤 pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime] (the Manager's read), PS 5.1 leaves it a
            # string (the setup script's read). Take either; never stringify a [datetime] and re-parse it.
            $ran = [datetime]::MinValue; $okDate = $false
            if ($r.ranUtc -is [datetime]) {
                $ran = $(if ($r.ranUtc.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($r.ranUtc, [DateTimeKind]::Utc) } else { $r.ranUtc.ToUniversalTime() }); $okDate = $true
            } else {
                $okDate = [datetime]::TryParse("$($r.ranUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$ran)
            }
            $v.ranUtc = $(if ($okDate) { $ran.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { "$($r.ranUtc)" }); $v.ranBy = "$($r.ranBy)"
            $v.selfChecked = ("$($r.ranBy)" -eq 'engine self-check')
            $v.engineObjectId = "$(Get-PimWorkloadPrereqRecordField -Object $r -Name 'engineObjectId')"
            $v.failed = @($r.failed | Where-Object { $_ }); $v.pending = @($r.pending | Where-Object { $_ })
            $v.checks = @(@($r.checks | Where-Object { $_ }) | ForEach-Object {
                $id = "$($_.id)"; $s = "$($_.status)"; $d = Get-PimWorkloadPrereqCheckDef -Id $id
                Copy-PimWorkloadPrereqCheck -Check $_ -Set @{
                    canConfirm  = ((-not [bool]$_.ok) -and $s -ne 'confirmed' -and [bool](Test-PimWorkloadPrereqConfirmable -Id $id -Status $s))
                    canSkip     = ([bool]($d -and $d.ContainsKey('dataOperations') -and $d.dataOperations) -and $s -ne 'skipped' -and -not [bool]$_.ok)
                    canWithdraw = ($s -in @('confirmed', 'skipped'))
                    kind        = $(if ($d) { "$($d.kind)" } else { '' })
                } })
            $st = "$($r.state)"
            if (-not $st) { $st = $(if ([bool]$r.ok) { 'ok' } else { 'failed' }) }
            if (-not $okDate) { $st = 'incomplete'; $v.pending = @($v.pending) + @('the stored run has no readable date') }
            else {
                $v.ageDays = [Math]::Floor(($NowUtc.ToUniversalTime() - $ran).TotalDays)
                if ($st -eq 'ok' -and $v.ageDays -gt $StaleDays) { $st = 'stale' }
            }
            $v.state = $st
            $v.chip = $(switch ($st) { 'ok' { 'green' } 'failed' { 'red' } default { 'amber' } })
            $envW = @{}; foreach ($k in @($Env.Keys)) { $envW[$k] = $Env[$k] }
            $v.command = Get-PimWorkloadPrereqFixCommand -Workload $w -Record $r -Env $envW
            # PIM 100.108 (a): every open Power BI step NAMES the group and the identity (a record from before this, or a
            # check re-created by Confirm / Withdraw, carries only the general step).
            if ($w -eq 'PowerBI') {
                $facts = Get-PimPowerBiPrereqFacts -Record $r
                $steps = Get-PimPowerBiPrereqSteps -GroupName $facts.groupName -GroupId $facts.groupId -Identity $facts.identity
                $stepOf = @{ 'powerbi.group' = 'group'; 'powerbi.groupMember' = 'groupMember'; 'powerbi.tenantSetting' = 'tenantSetting' }
                $v.checks = @(@($v.checks) | ForEach-Object {
                    $cid = "$($_.id)"
                    if ($stepOf.ContainsKey($cid) -and -not [bool]$_.ok -and "$($_.status)" -ne 'confirmed') { Copy-PimWorkloadPrereqCheck -Check $_ -Set @{ manualStep = $steps[$stepOf[$cid]] } } else { $_ } })
            }
            # PIM 100.108 (e): ready only with the confirmation call answered 200 as the engine.
            $v.ready = ($st -eq 'ok')
            $confDef = @(@($cat[$w].checks) | Where-Object { $_.ContainsKey('confirmation') -and $_.confirmation })[0]
            if ($confDef) {
                $cc = @(@($v.checks) | Where-Object { "$($_.id)" -eq "$($confDef.id)" })[0]
                $cs = if ($cc) { "$($cc.status)" } else { 'notChecked' }
                $cd = if ($cc) { "$($cc.detail)".Trim() } else { '' }
                $v.confirmation = [ordered]@{ id = "$($confDef.id)"; name = "$($confDef.name)"; status = $cs; ok = ($cs -eq 'ok'); detail = $cd }
                if ($st -eq 'ok' -and $cs -ne 'ok') {
                    $v.ready = $false
                    $v.chip = 'amber'
                    $v.notReady = if ($cs -eq 'failed') { "PIM's own call did not get through, so this workload is not counted as ready: $(if ($cd) { $cd } else { "$($confDef.name) failed" })" }
                                  else { "PIM has not confirmed this with its own call yet ($($confDef.name)) -- press Check again. Until then it is not counted as ready." }
                }
            }
        }
        $v.next = Get-PimWorkloadPrereqNextStep -State $v.state -Command $v.command -Confirmable @($v.checks | Where-Object { $_.canConfirm }).Count
        $out.Add([pscustomobject]$v)
    }
    return $out.ToArray()
}
