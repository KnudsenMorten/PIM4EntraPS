<#
  PIM4EntraPS -- ACTIVE-ASSIGNMENTS SNAPSHOT (REQUIREMENTS §70.1b option 2).

  🔴 WHY THIS FILE EXISTS. The Manager serves every HTTP request on ONE loop. GET
  /api/active-assignments used to read every Entra-role / Azure-RBAC / PIM-for-Groups active
  assignment LIVE (Graph throttles PIM-for-Groups; measured 140-170 s on internal), and every other
  user of the Manager waited behind it ("Jobs / Engine runs pages take forever", ~2.5 min freezes).

  🔑 THE READ MOVED TO THE SCHEDULER. The compute below (Invoke-PimActiveAssignmentsSnapshot) is the
  former Get-PimActiveAssignmentsCached body, moved here verbatim in behaviour -- same row shape,
  counts, surfaceErrors and hints -- so the scheduler tick (ca-pim-tick / VisualCron) can run it as
  job 'active-assignments-snapshot' and write the result to SQL pim.TenantCache kind
  'active-assignments'. The Manager only READS that row (ConvertTo-PimActiveAssignmentsSnapshotView)
  and asks for a refresh by queueing a trigger (Request-PimActiveAssignmentsSnapshotRefresh).

  🔒 THE MANAGER NEVER COMPUTES THE SNAPSHOT (operator, 2026-09-13: near-real-time with a delay of a
  few hours is acceptable; no Manager-side "capture when idle" path, because a capture that is running
  when a user arrives freezes them). The Manager dot-sources this file only for the principal/role
  lookup helpers other endpoints share; the job handler is registered ONLY by
  tools/pim-scheduler/Start-PimScheduler.ps1 (Register-PimActiveAssignmentsSnapshotHandler).

  Dependencies: engine/_shared/PIM-Rest.ps1 (Invoke-PimGraph / Invoke-PimArm / Invoke-PimGraphBatchGet /
  Get-PimArmActiveRoleAssignmentsViaArg / ConvertTo-PimSdkShape), tools/pim-manager/_tenantSync.ps1
  (Assert-PimTenantConnectionContext, Connect-PimManagerGraph/Az, Get-/Set-PimTenantCacheEntry) and,
  for the trigger, engine/_shared/PIM-Scheduler.ps1 (Add-PimJobTrigger). Runs on pwsh 7 and 5.1.
#>

Set-StrictMode -Off

# The job type + the pim.TenantCache kind, named once.
$script:PimActiveAssignmentsSnapshotJobType   = 'active-assignments-snapshot'
$script:PimActiveAssignmentsSnapshotCacheKind = 'active-assignments'
$script:PimActiveAssignmentsSnapshotDefaultCadenceMinutes = 120

# ---------------------------------------------------------------------------
# v2.4.2 Revoke tab -- bulk-revoke of active PIM assignments.
#
# §70.1b option 2: the read is a SCHEDULER job now (see the header). The Manager serves the stored
# snapshot; Refresh queues a trigger. Three sources are combined into a single row set:
#
#   * Entra-role active assignments:
#       Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All
#       (TODO v2.4.3 -- add Get-EntraRoleAssignmentsPreloaded helper to the
#        engine's _shared/PIM-Functions.psm1, mirroring the v2.4.0
#        Get-PimGroupSchedulesPreloaded pattern. For now we call directly.)
#
#   * Azure-RBAC active assignments:
#       Get-AzActiveRoleAssignmentsViaArg  (v2.4.0 helper, Search-AzGraph)
#
#   * PIM-for-Groups active assignments:
#       Get-PimGroupSchedulesPreloaded     (v2.4.0 helper, single Graph call)
#
# The Revoke tab in the Manager only acts on ACTIVE (Assigned) rows -- not
# Eligible -- because eligibility removal is a different operator workflow
# already handled by the Baseline engine. The engine PIM-Assignment-Revoker
# still supports both; the GUI is the bulk-revoke subset.
# ---------------------------------------------------------------------------

function Initialize-PimManagerTenantConnection {
    # Lazy-connect Graph + Az on first Revoke tab use. Reuses the
    # _tenantSync.ps1 helpers so we share the engine-SPN connection logic
    # (no interactive Connect-MgGraph / Connect-AzAccount ever).
    if ($script:PimManagerTenantConnected) { return }
    if (-not (Get-Command Assert-PimTenantConnectionContext -ErrorAction SilentlyContinue)) {
        throw "_tenantSync.ps1 helpers not loaded -- file missing next to Open-PimManager.ps1"
    }
    $tenantId = Assert-PimTenantConnectionContext
    # A REST-only host (the scheduler tick sets $global:PIM_UseGraphSdk = $false) mints its own tokens per
    # call through PIM-Rest.ps1. Connect-PimManagerGraph/Az would otherwise try an SDK sign-in whenever the
    # Graph/Az modules merely happen to be INSTALLED on the host (a VM running the tick from VisualCron),
    # and throw for want of the SDK-style HighPriv globals the tick never sets.
    if (-not (Test-PimActiveAssignmentsRestOnly)) {
        Connect-PimManagerGraph -TenantId $tenantId
        Connect-PimManagerAz    -TenantId $tenantId
    }
    $script:PimManagerTenantConnected = $true
}

function Test-PimActiveAssignmentsRestOnly {
    # True when this process has explicitly opted out of the Graph/Az SDK ($global:PIM_UseGraphSdk = $false,
    # which the scheduler tick and the REST engine set) AND the REST client is loaded. Unset keeps the old
    # detection (SDK cmdlet present or not), so the Manager's behaviour is unchanged.
    return ([bool](Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and ($global:PIM_UseGraphSdk -is [bool]) -and (-not $global:PIM_UseGraphSdk))
}

function Get-PimActiveAssignmentsGroupPrefix {
    # The PIM-group naming prefix (e.g. 'PIM-') from the naming convention in pim.Settings. Same rule as
    # Get-PimNamePrefix (PIM-Functions.psm1: the literal text before the first {Token}), inlined so a host
    # that does not import that 13k-line module -- the scheduler tick -- resolves the SAME prefix instead of
    # silently falling back to 'PIM-'. A prefix shorter than 3 characters is ignored, as before.
    $pfx = 'PIM-'
    try {
        $pat = $null
        if ($global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern) { $pat = "$($global:PIM_NamingConventions.PimGroupPattern)" }
        if ($pat) {
            $p = if (Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue) { Get-PimNamePrefix -Pattern $pat }
                 else { $i = $pat.IndexOf('{'); if ($i -lt 0) { $pat } else { $pat.Substring(0, $i) } }
            if ($p -and $p.Length -ge 3) { $pfx = $p }
        }
    } catch { }
    return $pfx
}

function Get-PimManagerLookupCaches {
    # Populate $script:PimManager_Users / Groups / Roles for principal +
    # role-display-name resolution in the active-assignments row builder.
    # Pulled once per server start; refreshed only when -Force passed.
    param([switch]$Force)
    if (-not $Force -and $script:PimManager_LookupCachesLoaded) { return }

    Initialize-PimManagerTenantConnection

    Write-Host "  [revoke] loading principal + role lookup caches (one-shot per session) ..." -ForegroundColor DarkGray
    # REST-only (hosted container): no Graph SDK -> pull via PIM-Rest's
    # Invoke-PimGraph and re-shape to SDK casing (.Id/.DisplayName/.UPN) so the
    # row-builder + id indexes below are unchanged.
    $restGraph = ((Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and -not (Get-Command Get-MgUser -ErrorAction SilentlyContinue)) -or (Test-PimActiveAssignmentsRestOnly)

    # Users. The admin filter (Get-PimAdminsFiltered) needs the engine module;
    # without it (REST-only) pull the admin-pattern users directly, else all.
    try {
        if ((-not $restGraph) -and (Get-Command Get-PimAdminsFiltered -ErrorAction SilentlyContinue)) {
            $script:PimManager_Users = @(Get-PimAdminsFiltered)
        } elseif ($restGraph) {
            # 🔒 DELIBERATELY UNFILTERED (operator, 2026-09-12: "for the revoke solution, we dont
            # filter as it contains legacy assignements").
            # This list resolves PRINCIPAL NAMES for the revoke screen, and that screen must show
            # LEGACY assignments -- grants to accounts that predate, or sit outside, the admin
            # naming convention. Filtering by AdminAccountPatterns here (briefly shipped in
            # 2.4.330 and reverted) would blank the name of exactly the assignments an operator
            # most needs to see and revoke.
            # 🪤 So the 250k-tenant fix here is NOT a prefix filter -- a filter trades a slow screen
            # for a WRONG one. It is to resolve only the ids the rows actually reference.
            # ✅ §67.2 (2026-09-13): nothing is pre-loaded. Every row builder already ends with ONE
            # /directoryObjects/getByIds call for the ids it references (Resolve-PimManagerPrincipalIdBatch),
            # and that call now also fills $script:PimManager_UserById for the users it returns -- so every
            # consumer of the user index sees the same UPN + display name the directory pull gave, for
            # exactly the principals on screen, whether the tenant has 300 users or 250,000.
            $script:PimManager_Users = @()
        } else {
            $script:PimManager_Users = @(Get-MgUser -All)
        }
    } catch {
        Write-Warning "  [revoke] user cache load failed: $($_.Exception.Message). Principal names may be blank."
        $script:PimManager_Users = @()
    }
    # Groups (PIM-prefix filter if naming-conventions present, else full set).
    try {
        if ((-not $restGraph) -and (Get-Command Get-PimGroupsFiltered -ErrorAction SilentlyContinue)) {
            $script:PimManager_Groups = @(Get-PimGroupsFiltered)
        } elseif ($restGraph) {
            $pfx = Get-PimActiveAssignmentsGroupPrefix
            $f =[uri]::EscapeDataString("startswith(displayName,'$pfx')")
            $script:PimManager_Groups = @(Invoke-PimGraph -Path "/groups?`$filter=$f&`$select=id,displayName,description,groupTypes&`$top=999" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_Groups = @(Get-MgGroup -All)
        }
    } catch {
        Write-Warning "  [revoke] group cache load failed: $($_.Exception.Message). Group names may be blank."
        $script:PimManager_Groups = @()
    }
    # Entra role definitions (small, single call, no filtering).
    try {
        if ($restGraph) {
            $script:PimManager_EntraRoles = @(Invoke-PimGraph -Path "/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,templateId" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_EntraRoles = @(Get-MgRoleManagementDirectoryRoleDefinition -All)
        }
    } catch {
        Write-Warning "  [revoke] entra role-definition cache load failed: $($_.Exception.Message). Entra role names may be blank."
        $script:PimManager_EntraRoles = @()
    }
    # AU directory cache (for /administrativeUnits/<id> scope display).
    try {
        if ($restGraph) {
            $script:PimManager_AUs = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_AUs = @(Get-MgDirectoryAdministrativeUnit -All)
        }
    } catch {
        $script:PimManager_AUs = @()
    }

    # Engine helpers (Resolve-PimGroupCached etc.) read $Global:Users_All_ID /
    # $Global:Groups_All_ID. Mirror our caches there so the v2.4.0 helpers
    # stay first-class.
    $Global:Users_All_ID  = $script:PimManager_Users
    $Global:Groups_All_ID = $script:PimManager_Groups

    # Id-keyed indexes: the row builder resolves principal/role/AU labels per
    # assignment row, and a linear scan per row is O(rows x principals) --
    # measurably seconds on a 944-row tenant. Hashtables make it O(rows).
    $script:PimManager_UserById  = @{}
    foreach ($u in $script:PimManager_Users)  { if ($u -and $u.Id)  { $script:PimManager_UserById["$($u.Id)"]  = $u } }
    # §67.2: users already resolved by id this session stay indexed across a -Force refresh.
    foreach ($rk in @(if ($script:PimManager_ResolvedById -is [hashtable]) { $script:PimManager_ResolvedById.Keys })) {
        $rv = $script:PimManager_ResolvedById[$rk]
        if ($rv -and "$($rv.kind)" -eq 'user') { Add-PimManagerUserIndexEntry -Id "$rk" -DisplayName "$($rv.displayName)" -UserPrincipalName "$($rv.userPrincipalName)" }
    }
    $script:PimManager_GroupById = @{}
    foreach ($g in $script:PimManager_Groups) { if ($g -and $g.Id)  { $script:PimManager_GroupById["$($g.Id)"] = $g } }
    $script:PimManager_RoleById  = @{}
    foreach ($r in $script:PimManager_EntraRoles) { if ($r -and $r.Id) { $script:PimManager_RoleById["$($r.Id)"] = $r } }
    $script:PimManager_AuById    = @{}
    foreach ($a in $script:PimManager_AUs) { if ($a -and $a.Id) { $script:PimManager_AuById["$($a.Id)"] = $a } }

    $script:PimManager_LookupCachesLoaded = $true
}

# BUG-98 -- RESOLVE PRINCIPALS BY ID, NOT BY NAMING CONVENTION.
#
# The two caches above are built by FILTERED queries: users via /users, groups via
# startswith(displayName,'<PimGroupPattern prefix>'), and SERVICE PRINCIPALS NOT AT ALL. So the
# revoke table showed a bare objectId for
#   * every service principal            (never cached), and
#   * every group outside the PIM- prefix (filtered out).
# The operator saw both shapes in one list and asked "i see both, why". Resolved live
# 2026-08-30: the unresolved ids were groups and servicePrincipals, exactly as above.
#
# 🔑 A display-name resolver must NEVER depend on a naming convention being obeyed. This one
# asks Graph for the ids it actually has, in one batched call, and caches the answers.
if (-not ($script:PimManager_ResolvedById -is [hashtable])) { $script:PimManager_ResolvedById = @{} }

function Add-PimManagerUserIndexEntry {
    param([Parameter(Mandatory)][string]$Id, [string]$DisplayName, [string]$UserPrincipalName)
    if (-not ($script:PimManager_UserById -is [hashtable])) { $script:PimManager_UserById = @{} }
    if ($script:PimManager_UserById.ContainsKey($Id)) { return }
    # Property names are case-insensitive, so the SDK casing below also answers .id / .displayName.
    $script:PimManager_UserById[$Id] = [pscustomobject]@{ Id = $Id; DisplayName = $DisplayName; UserPrincipalName = $UserPrincipalName }
}

function Resolve-PimManagerPrincipalIdBatch {
    # Fill $script:PimManager_ResolvedById for every id not already known. /directoryObjects
    # /getByIds takes up to 1000 ids per call and returns users, groups AND servicePrincipals,
    # so ~700 assignment rows collapse to a single request. Best-effort: a failure here leaves
    # the ids unresolved (the caller still renders the GUID) and never breaks the table.
    param([string[]]$Ids)
    $need = @($Ids | Where-Object { $_ -and -not $script:PimManager_ResolvedById.ContainsKey("$_") } |
                     Select-Object -Unique)
    if (-not $need -or $need.Count -eq 0) { return }
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return }
    for ($i = 0; $i -lt $need.Count; $i += 1000) {
        $chunk = @($need[$i..([Math]::Min($i + 999, $need.Count - 1))])
        $answered = $false
        try {
            $body = @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 4
            $r = Invoke-PimGraph -Path '/directoryObjects/getByIds' -Method POST -Body $body
            $answered = $true
            foreach ($o in @($r.value)) {
                if (-not $o -or -not $o.id) { continue }
                $kind = ("$($o.'@odata.type')" -replace '#microsoft\.graph\.', '')
                $label = if ($o.userPrincipalName) { [string]$o.userPrincipalName } else { [string]$o.displayName }
                if (-not $label) { $label = [string]$o.id }
                $script:PimManager_ResolvedById["$($o.id)"] = [pscustomobject]@{ label = $label; kind = $kind; displayName = [string]$o.displayName; userPrincipalName = [string]$o.userPrincipalName }
                # §67.2: the user index is no longer a directory pull -- it is filled HERE, for the users a
                # screen actually references, in the same SDK shape the pull produced.
                if ($kind -eq 'user') { Add-PimManagerUserIndexEntry -Id "$($o.id)" -DisplayName ([string]$o.displayName) -UserPrincipalName ([string]$o.userPrincipalName) }
            }
        } catch {
            Write-Warning "  [revoke] principal batch resolve failed: $($_.Exception.Message). Some rows will show a raw object id."
        }
        # An id Graph did not return is DELETED (or not visible to us). Record that explicitly:
        # a role still held by a principal that no longer exists is a FINDING, not a blank.
        # 🔒 Only when Graph ANSWERED: a failed call proves nothing about the ids, and now that users are
        # resolved here too (§67.2) it would otherwise brand every admin "(deleted principal)" for the session.
        if (-not $answered) { continue }
        foreach ($id in $chunk) {
            if (-not $script:PimManager_ResolvedById.ContainsKey("$id")) {
                $script:PimManager_ResolvedById["$id"] = [pscustomobject]@{ label = '(deleted principal)'; kind = 'deleted' }
            }
        }
    }
}

function Resolve-PimManagerPrincipalLabel {
    # Try user UPN first, then group DisplayName, then the by-id resolver (BUG-98), then the
    # bare id. Hashtable lookups -- called once per assignment row (944 rows on a real tenant).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($PrincipalId)) {
        $u = $script:PimManager_UserById[$PrincipalId]
        if ($u.UserPrincipalName) { return [string]$u.UserPrincipalName }
        if ($u.DisplayName)       { return [string]$u.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) {
        $g = $script:PimManager_GroupById[$PrincipalId]
        if ($g.DisplayName) { return [string]$g.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($PrincipalId)) {
        $r = $script:PimManager_ResolvedById[$PrincipalId]
        if ($r -and $r.label) { return [string]$r.label }
    }
    return $PrincipalId
}

function Get-PimManagerPrincipalKind {
    # BUG-98: the GUI shows this as a small chip, so a group or an app is not mistaken for a
    # person on a screen whose whole job is deciding whose access to revoke.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById  -and $script:PimManager_UserById.ContainsKey($PrincipalId))  { return 'user' }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) { return 'group' }
    if ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($PrincipalId)) {
        return [string]$script:PimManager_ResolvedById[$PrincipalId].kind
    }
    return ''
}

function Resolve-PimManagerEntraRoleName {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return '' }
    # Trim a possible /providers/.../roleDefinitions/<guid> prefix.
    $guid = $RoleDefinitionId
    $slash = $RoleDefinitionId.LastIndexOf('/')
    if ($slash -ge 0 -and $slash -lt ($RoleDefinitionId.Length - 1)) {
        $guid = $RoleDefinitionId.Substring($slash + 1)
    }
    if ($script:PimManager_RoleById -and $script:PimManager_RoleById.ContainsKey($guid)) {
        $r = $script:PimManager_RoleById[$guid]
        if ($r.DisplayName) { return [string]$r.DisplayName }
    }
    return $guid
}

function Resolve-PimManagerDirectoryScope {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DirectoryScopeId)
    if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -eq '/')                       { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -like '/administrativeUnits/*') {
        $auId = ($DirectoryScopeId -split '/')[-1]
        if ($script:PimManager_AuById -and $script:PimManager_AuById.ContainsKey($auId)) {
            return '/AdministrativeUnits/' + [string]$script:PimManager_AuById[$auId].DisplayName
        }
        return $DirectoryScopeId
    }
    return $DirectoryScopeId
}

function Get-PimActiveAssignmentSurfaceHint {
    # Map a failed active-assignments surface + its error text to an ACTIONABLE
    # remediation: which Graph app-role / Azure RBAC role is needed and the exact
    # setup/Grant-PimGraphAppRoles.ps1 invocation. Returns '' when the failure is
    # not a recognised auth/permission failure (transport/transient -> retry).
    param(
        [Parameter(Mandatory)][ValidateSet('entra-role','azure-rbac','pim-for-groups')][string]$Surface,
        [string]$ErrorMessage = ''
    )
    $em = "$ErrorMessage"
    # Recognise the permission-failure signatures (Graph 403 / ARM AuthorizationFailed).
    $isAuth = ($em -match '(?i)\b(401|403)\b' -or
               $em -match '(?i)Authorization_RequestDenied|InsufficientPrivileges|insufficient privileges|Forbidden|AuthorizationFailed|does not have authorization|Authentication_MissingOrMalformed')
    switch ($Surface) {
        'entra-role' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read Entra-role active assignments " +
                    "(roleManagement/directory). Grant RoleManagement.Read.Directory (or RoleManagement.ReadWrite.Directory) " +
                    "via setup/Grant-PimGraphAppRoles.ps1 -TenantId <tid> -AdminClientId <mgmtSpn> -AdminCertThumbprint <thumb> -EngineAppId <engineSpn>.")
        }
        'pim-for-groups' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read PIM-for-Groups active assignments " +
                    "(identityGovernance/privilegedAccess/group). Grant PrivilegedAccess.Read.AzureADGroup " +
                    "(or PrivilegedAccess.ReadWrite.AzureADGroup) via setup/Grant-PimGraphAppRoles.ps1.")
        }
        'azure-rbac' {
            return ("Engine SPN cannot read Azure-RBAC active assignments. Grant it at least Reader on the " +
                    "target subscription(s) (Azure RBAC, not a Graph app-role) so " +
                    "Microsoft.Authorization/roleAssignmentScheduleInstances can be enumerated.")
        }
    }
    return ''
}

function Invoke-PimActiveAssignmentsSnapshot {
    # THE LIVE READ -- scheduler only (§70.1b option 2). Returns an ordered hashtable:
    #   @{ ok; rows = [...]; counts = @{...}; surfaceErrors; partial; loadedUtc; refreshedUtc; cacheHit=$false;
    #      elapsedSec; durationMs; error? }
    # This was the compute half of the Manager's Get-PimActiveAssignmentsCached, moved here unchanged in
    # behaviour (row shape, counts, surfaceErrors, hints). What is GONE is the in-process 5-minute cache and
    # the lazy PIM-Functions.psm1 import: the result is persisted to SQL by the job, and every reader in the
    # REST path lives in PIM-Rest.ps1 (the psm1 only fed the SDK branches, and Get-PimNamePrefix is inlined as
    # Get-PimActiveAssignmentsGroupPrefix).
    # 🔒 Never call this from the Manager: one run is 140-170 s of Graph reads, and the Manager's single request
    # loop would freeze every user for that long. Test-PimActiveAssignmentsSnapshot asserts it.
    # -Fresh: reload the group/role/AU lookups AND forget principal names resolved earlier in this process, so a
    # long-running scheduler loop does not keep a renamed or deleted principal's old label for ever.
    [CmdletBinding()]
    param([switch]$Fresh)

    if ($Fresh) { $script:PimManager_ResolvedById = @{} }
    # Initial connect + lookup caches (idempotent).
    Initialize-PimManagerTenantConnection
    Get-PimManagerLookupCaches -Force:$Fresh

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.ArrayList

    # Per-surface failure ledger. Each entry: @{ surface; error; hint }.
    # When a surface FETCH fails (auth/permission/transport) we record it here
    # instead of silently swallowing to @(). This is what lets the endpoint and
    # GUI tell "genuinely no active assignments" apart from "we could not read
    # them" -- the old code returned ok=$true,total=0 for BOTH, which surfaced as
    # the misleading "Cache may be empty -- click Refresh." (root cause).
    $surfaceErrors = New-Object System.Collections.ArrayList

    # REST-only (hosted container): mint tokens + read Graph/ARM via PIM-Rest.ps1
    # -- the Graph/Az PowerShell SDK is not installed in the image.
    $restGraph = ((Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and -not (Get-Command Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ErrorAction SilentlyContinue)) -or (Test-PimActiveAssignmentsRestOnly)
    $restArm   = ((Get-Command Invoke-PimArm   -ErrorAction SilentlyContinue) -and -not (Get-Command Get-AzActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue)) -or ((Test-PimActiveAssignmentsRestOnly) -and [bool](Get-Command Invoke-PimArm -ErrorAction SilentlyContinue))

    # ---- Entra-role active assignments -------------------------------------
    # TODO v2.4.3: replace with Get-EntraRoleAssignmentsPreloaded helper once
    # ported into engine/_shared/PIM-Functions.psm1 (mirror of the
    # Get-PimGroupSchedulesPreloaded pattern). For now: direct -All call.
    $entraRows = @()
    try {
        if ($restGraph) {
            # REST: same collection, camelCase -> reshape to SDK casing so the
            # ScheduleInfo/Expiration nested fields below resolve unchanged.
            $entraRows = @(Invoke-PimGraph -Path '/roleManagement/directory/roleAssignmentSchedules' -All | ConvertTo-PimSdkShape)
        } else {
            $entraRows = @(Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop)
        }
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role assignment-schedules load failed: $em"
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'entra-role'
            error   = $em
            hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage $em)
        })
        $entraRows = @()
    }
    foreach ($e in $entraRows) {
        if (-not $e) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$e.PrincipalId)
        $roleLabel      = Resolve-PimManagerEntraRoleName -RoleDefinitionId ([string]$e.RoleDefinitionId)
        $scopeLabel     = Resolve-PimManagerDirectoryScope -DirectoryScopeId ([string]$e.DirectoryScopeId)
        # SDK objects expose PascalCase; REST returns camelCase nested objects
        # (ConvertTo-PimSdkShape only aliases the top level). Tolerate both.
        $si = if ($e.ScheduleInfo) { $e.ScheduleInfo } else { $e.scheduleInfo }
        $start = $null; $end = $null
        if ($si) {
            $sdt = if ($si.StartDateTime) { $si.StartDateTime } else { $si.startDateTime }
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = if ($si.Expiration) { $si.Expiration } else { $si.expiration }
            if ($exp) {
                $edt = if ($exp.EndDateTime) { $exp.EndDateTime } else { $exp.endDateTime }
                if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} }
            }
        }
        [void]$rows.Add([ordered]@{
            id               = "entra-role:$($e.Id)"
            type             = 'entra-role'
            principal        = $principalLabel
            principalId      = [string]$e.PrincipalId
            role             = $roleLabel
            roleDefinitionId = [string]$e.RoleDefinitionId
            scope            = $scopeLabel
            directoryScopeId = [string]$e.DirectoryScopeId
            start            = $start
            end              = $end
            justification    = ''  # Entra role assignment schedules don't carry the original activation justification on the assignment object.
        })
    }

    # ---- Azure-RBAC active assignments -------------------------------------
    # REQUIREMENTS 67.3: ONE Azure Resource Graph query over REST (Get-PimArmActiveRoleAssignmentsViaArg,
    # PIM-Rest.ps1) returns every role assignment the engine identity can see -- management groups,
    # subscriptions, resource groups, resources -- with the role name joined in. It replaces a
    # subscriptions list plus one instances read per subscription, which also never saw a management group
    # without a subscription under it. Each row carries its roleAssignmentId, which an ACTIVE revoke needs
    # (the per-subscription rows had none, so queueing one threw). If the query fails the old walk still runs.
    $azRows = @()
    $argDone = $false
    if ((Get-Command Get-PimArmActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) -and (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
        try {
            $azRows = @(Get-PimArmActiveRoleAssignmentsViaArg | ForEach-Object {
                [pscustomobject]@{ Id = $_.Id; PrincipalId = $_.PrincipalId; RoleDefinitionId = $_.RoleDefinitionId; RoleDefinitionName = $_.RoleDefinitionName
                                   Scope = $_.Scope; RoleAssignmentId = $_.Id; RoleAssignmentName = $_.Name; PrincipalType = $_.PrincipalType }
            })
            $argDone = $true
            Write-Host ("  [revoke] azure-rbac: {0} role assignment(s) from one Resource Graph query" -f $azRows.Count) -ForegroundColor DarkGray
        } catch {
            Write-Warning ("  [revoke] Resource Graph role-assignment query failed ({0}) -- falling back to the per-subscription read." -f $_.Exception.Message)
            $azRows = @()
            $restArm = [bool](Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)
        }
    }
    if ($argDone) { }
    elseif ($restArm) {
        # REST: enumerate active role-assignment-schedule-instances at each
        # subscription scope (ARM has no tenant-wide list). PrincipalNotFound /
        # auth errors per-sub are tolerated so one bad sub doesn't blank the tab.
        try {
            $subs = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)
            if ($subs.Count -eq 0) {
                Write-Warning "  [revoke] ARM returned 0 subscriptions for this identity -- Azure RBAC rows will be empty (engine SPN has no subscription scope / no Reader)."
                [void]$surfaceErrors.Add([ordered]@{
                    surface = 'azure-rbac'
                    error   = 'ARM returned 0 subscriptions visible to the engine identity.'
                    hint    = 'Grant the engine SPN at least Reader on the target subscription(s) so Azure-RBAC active assignments can be enumerated.'
                })
            }
            foreach ($s in $subs) {
                $scope = "/subscriptions/$($s.subscriptionId)"
                try {
                    foreach ($ri in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" -ApiVersion '2020-10-01-preview' -All)) {
                        $p = $ri.properties
                        $rdId = "$($p.roleDefinitionId)"
                        $azRows += [pscustomobject]@{
                            Id                 = "$($ri.id)"
                            PrincipalId        = "$($p.principalId)"
                            RoleDefinitionId   = $rdId
                            RoleDefinitionName = ($rdId -split '/' | Select-Object -Last 1)
                            Scope              = "$($p.scope)"
                        }
                    }
                } catch { Write-Warning ("  [revoke] ARM role-assignment instances for {0} failed: {1}" -f $scope, $_.Exception.Message) }
            }
        } catch {
            $em = "$($_.Exception.Message)"
            Write-Warning "  [revoke] ARM subscriptions enumeration failed: $em. Azure RBAC rows will be empty."
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'azure-rbac'
                error   = $em
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $em)
            })
            $azRows = @()
        }
    } elseif (Get-Command Get-AzActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) {
        try {
            $azRows = @(Get-AzActiveRoleAssignmentsViaArg)
        } catch {
            $em = "$($_.Exception.Message)"
            Write-Warning "  [revoke] Get-AzActiveRoleAssignmentsViaArg failed: $em"
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'azure-rbac'
                error   = $em
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $em)
            })
            $azRows = @()
        }
    } else {
        $em = 'Azure-RBAC reader not available (no ARM REST helper Invoke-PimArm + no engine _shared/PIM-Functions.psm1 reader).'
        Write-Warning "  [revoke] $em Azure RBAC rows will be empty."
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'azure-rbac'
            error   = $em
            hint    = 'Ensure engine/_shared/PIM-Rest.ps1 is dot-sourced (hosted) so Invoke-PimArm is available.'
        })
    }
    foreach ($a in $azRows) {
        if (-not $a) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$a.PrincipalId)
        $roleName       = if ($a.RoleDefinitionName) { [string]$a.RoleDefinitionName } else { [string]$a.RoleDefinitionId }
        $azRow = [ordered]@{
            id               = "azure-rbac:$($a.Id)"
            type             = 'azure-rbac'
            principal        = $principalLabel
            principalId      = [string]$a.PrincipalId
            role             = $roleName
            roleDefinitionId = [string]$a.RoleDefinitionId
            scope            = [string]$a.Scope
            directoryScopeId = ''
            start            = ''  # ARG row doesn't carry start/end for the assignment record.
            end              = ''
            justification    = ''
        }
        if ($a.PSObject.Properties['RoleAssignmentId'] -and "$($a.RoleAssignmentId)".Trim()) {
            $azRow['roleAssignmentId']   = [string]$a.RoleAssignmentId
            $azRow['roleAssignmentName'] = [string]$a.RoleAssignmentName
        }
        [void]$rows.Add($azRow)
    }

    # ---- PIM-for-Groups active assignments ---------------------------------
    # Graph REFUSES an unfiltered list on assignmentSchedules ('MissingParameters:
    # The required parameters GroupId or PrincipalId is missing') -- both the
    # engine's bulk preload and a naive -All call get BadRequest. The supported
    # shape is one filtered query per group. Two scale guards:
    #   1. Only PIM-convention groups qualify (the lookup cache can contain the
    #      whole tenant when the naming filter is broad; dynamic groups fail
    #      with ResourceTypeNotSupported anyway).
    #   2. Queries go through /v1.0/$batch, 20 per round-trip -- a per-group
    #      sequential loop took >4 minutes on a real tenant.
    $pimGroupRows = @()
    $pimPrefix = Get-PimActiveAssignmentsGroupPrefix
    $pimGroupsToQuery = @($script:PimManager_Groups | Where-Object { $_ -and $_.Id -and $_.DisplayName -and ([string]$_.DisplayName).StartsWith($pimPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    # A DYNAMIC-membership group cannot carry a PIM-for-Groups assignment (Graph answers
    # ResourceTypeNotSupported), so its request can only fail. The lookup cache now selects groupTypes,
    # which lets the read skip them instead of spending a batch slot to collect a known error.
    $pimDynamicSkipped = @($pimGroupsToQuery | Where-Object { @($_.GroupTypes) -contains 'DynamicMembership' }).Count
    if ($pimDynamicSkipped) { $pimGroupsToQuery = @($pimGroupsToQuery | Where-Object { -not (@($_.GroupTypes) -contains 'DynamicMembership') }) }
    if ($pimGroupsToQuery.Count -gt 0 -and (Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue)) {
        # REQUIREMENTS 67.1: the SAME one-filtered-query-per-group reads, through the engine's shared batch
        # reader -- which also follows @odata.nextLink (the inline loop below kept only the first page) and
        # re-runs a throttled (429) or 5xx request on its own instead of counting it as a failed group.
        $gFail = 0
        $gFirstErr = $null
        $gRes = Invoke-PimGraphBatchGet -Paths @($pimGroupsToQuery | ForEach-Object { "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($_.Id)'" })
        for ($i = 0; $i -lt $pimGroupsToQuery.Count; $i++) {
            $gr = $gRes[$i]
            if ($gr -and $gr.ok) { foreach ($v in @($gr.items)) { if ($null -ne $v) { $pimGroupRows += $v } }; continue }
            $gFail++
            $errText = if ($gr) { "$($gr.error)" } else { 'no response' }
            if (-not $gFirstErr -and $gr -and ($gr.status -eq 401 -or $gr.status -eq 403 -or $errText -match 'HTTP (401|403)\b')) { $gFirstErr = $errText }
            if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $pimGroupsToQuery[$i].DisplayName, $errText) }
        }
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        if ($pimGroupRows.Count -eq 0 -and $gFail -ge $pimGroupsToQuery.Count -and $gFirstErr) {
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'pim-for-groups'
                error   = $gFirstErr
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr)
            })
        }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips; {3} dynamic group(s) skipped)" -f $pimGroupRows.Count, $pimGroupsToQuery.Count, [Math]::Ceiling($pimGroupsToQuery.Count / 20), $pimDynamicSkipped) -ForegroundColor DarkGray
    } elseif ($pimGroupsToQuery.Count -gt 0) {
        $gFail = 0
        $gFirstErr = $null
        for ($ofs = 0; $ofs -lt $pimGroupsToQuery.Count; $ofs += 20) {
            $slice = $pimGroupsToQuery[$ofs..([Math]::Min($ofs + 19, $pimGroupsToQuery.Count - 1))]
            $requests = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $slice.Count; $i++) {
                [void]$requests.Add(@{
                    id     = "$i"
                    method = 'GET'
                    url    = "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($slice[$i].Id)'"
                })
            }
            try {
                if ($restGraph) {
                    # REST: Invoke-PimGraph posts the JSON batch with its own app-only token.
                    $resp = Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = $requests.ToArray() }
                } else {
                    $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Body (@{ requests = $requests.ToArray() } | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
                }
                foreach ($br in @($resp.responses)) {
                    if ($br.status -ge 200 -and $br.status -lt 300 -and $br.body -and $br.body.value) {
                        foreach ($v in @($br.body.value)) { $pimGroupRows += $v }
                    } elseif ($br.status -ge 400) {
                        $gFail++
                        $errCode = if ($br.body -and $br.body.error) { $br.body.error.code } else { $br.status }
                        $errMsg  = if ($br.body -and $br.body.error -and $br.body.error.message) { $br.body.error.message } else { "$errCode" }
                        if (-not $gFirstErr -and ($br.status -eq 401 -or $br.status -eq 403)) { $gFirstErr = "HTTP $($br.status) $errCode : $errMsg" }
                        if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $slice[[int]$br.id].DisplayName, $errCode) }
                    }
                }
            } catch {
                $gFail += $slice.Count
                if (-not $gFirstErr) { $gFirstErr = "$($_.Exception.Message)" }
                if ($gFail -le 25) { Write-Warning "  [revoke] `$batch round-trip failed: $($_.Exception.Message)" }
            }
        }
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        # Only a surface-level error when EVERY queried group failed AND we got
        # nothing back -- a few per-group failures (e.g. dynamic groups) are
        # tolerated and must not mask a partially-successful read.
        if ($pimGroupRows.Count -eq 0 -and $gFail -ge $pimGroupsToQuery.Count -and $gFirstErr) {
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'pim-for-groups'
                error   = $gFirstErr
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr)
            })
        }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips)" -f $pimGroupRows.Count, $pimGroupsToQuery.Count, [Math]::Ceiling($pimGroupsToQuery.Count / 20)) -ForegroundColor DarkGray
    } else {
        Write-Warning ("  [revoke] no '{0}'-prefixed groups in the lookup cache. PIM-for-Groups rows will be empty." -f $pimPrefix)
    }
    # Casing-tolerant property read: SDK objects are PascalCase, REST/$batch
    # bodies are camelCase. Returns the first present alias (or '').
    $pf = {
        param($Obj, [string[]]$Names)
        foreach ($n in $Names) { $pr = $Obj.PSObject.Properties[$n]; if ($pr -and $null -ne $pr.Value) { return $pr.Value } }
        return $null
    }
    foreach ($p in $pimGroupRows) {
        if (-not $p) { continue }
        $principalId = "$(& $pf $p @('PrincipalId','principalId'))"
        $groupId     = "$(& $pf $p @('GroupId','groupId'))"
        $itemId      = "$(& $pf $p @('Id','id'))"
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId $principalId
        # Group display name from cache, fall back to embedded Group.DisplayName.
        $groupLabel = ''
        # Id-keyed lookup (built with the caches) -- the old linear scan was O(rows x groups).
        if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($groupId)) {
            $groupLabel = [string]$script:PimManager_GroupById[$groupId].DisplayName
        } elseif ($script:PimManager_Groups -and -not $script:PimManager_GroupById) {
            foreach ($g in $script:PimManager_Groups) {
                if ($g -and "$($g.Id)" -eq $groupId) { $groupLabel = [string]$g.DisplayName; break }
            }
        }
        $grp = & $pf $p @('Group','group')
        if (-not $groupLabel -and $grp) { $gdn = & $pf $grp @('DisplayName','displayName'); if ($gdn) { $groupLabel = [string]$gdn } }
        if (-not $groupLabel) { $groupLabel = $groupId }
        $si = & $pf $p @('ScheduleInfo','scheduleInfo')
        $start = $null; $end = $null
        if ($si) {
            $sdt = & $pf $si @('StartDateTime','startDateTime')
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = & $pf $si @('Expiration','expiration')
            if ($exp) { $edt = & $pf $exp @('EndDateTime','endDateTime'); if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} } }
        }
        $access = "$(& $pf $p @('AccessId','accessId'))"; if (-not $access) { $access = 'member' }
        $just   = "$(& $pf $p @('Justification','justification'))"
        [void]$rows.Add([ordered]@{
            id               = "pim-for-groups:$itemId"
            type             = 'pim-for-groups'
            principal        = $principalLabel
            principalId      = $principalId
            role             = "$groupLabel ($access)"
            roleDefinitionId = ''
            scope            = $groupLabel
            directoryScopeId = ''
            groupId          = $groupId
            accessId         = $access
            start            = $start
            end              = $end
            justification    = $just
        })
    }

    # ---- BUG-98: second pass -- resolve every principal that the filtered caches missed ----
    # Done ONCE here rather than per surface: all three row builders have run, so the distinct
    # id set is complete and ~700 rows collapse into a single /directoryObjects/getByIds call.
    # Every row also gains principalKind so the GUI can tell a person from a group or an app on
    # a screen whose whole job is deciding whose access to revoke.
    try {
        $unresolved = @($rows | Where-Object { $_.principalId -and ("$($_.principal)" -eq "$($_.principalId)" -or -not $_.principal) } |
                                ForEach-Object { [string]$_.principalId } | Select-Object -Unique)
        if ($unresolved.Count -gt 0) {
            Write-Host ("  [revoke] resolving {0} principal id(s) the name caches did not cover ..." -f $unresolved.Count) -ForegroundColor DarkGray
            Resolve-PimManagerPrincipalIdBatch -Ids $unresolved
        }
        foreach ($row in $rows) {
            if (-not $row.principalId) { continue }
            if (-not $row.principal -or "$($row.principal)" -eq "$($row.principalId)") {
                $row.principal = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$row.principalId)
            }
            $row['principalKind'] = Get-PimManagerPrincipalKind -PrincipalId ([string]$row.principalId)
        }
    } catch {
        Write-Warning "  [revoke] principal second-pass resolve failed: $($_.Exception.Message)"
    }

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $counts = [ordered]@{
        total           = $rows.Count
        'entra-role'    = @($rows | Where-Object { $_.type -eq 'entra-role' }).Count
        'azure-rbac'    = @($rows | Where-Object { $_.type -eq 'azure-rbac' }).Count
        'pim-for-groups' = @($rows | Where-Object { $_.type -eq 'pim-for-groups' }).Count
    }
    Write-Host ("  [revoke] active-assignments loaded: {0} total ({1}e + {2}a + {3}g) in {4}s" -f $counts.total, $counts['entra-role'], $counts['azure-rbac'], $counts['pim-for-groups'], $elapsed) -ForegroundColor DarkGray

    $errArr = $surfaceErrors.ToArray()
    if ($errArr.Count -gt 0) {
        Write-Warning ("  [revoke] {0} surface(s) could NOT be read: {1}" -f $errArr.Count, (($errArr | ForEach-Object { $_.surface }) -join ', '))
    }
    # A read is FULLY-FAILED (not "empty") when nothing came back AND at least one
    # surface raised an auth/permission/transport error. The endpoint flags that
    # so the GUI shows an actionable error instead of "Cache may be empty".
    $allFailedEmpty = ($rows.Count -eq 0 -and $errArr.Count -gt 0)

    $loadedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $payload = [ordered]@{
        ok            = (-not $allFailedEmpty)
        rows          = $rows.ToArray()
        counts        = $counts
        surfaceErrors = $errArr
        partial       = ($rows.Count -gt 0 -and $errArr.Count -gt 0)
        loadedUtc     = $loadedUtc
        refreshedUtc  = $loadedUtc
        cacheHit      = $false
        elapsedSec    = $elapsed
        durationMs    = [int64][math]::Round($sw.Elapsed.TotalMilliseconds, 0)
    }
    if ($allFailedEmpty) {
        $payload.error = "Active PIM assignments could not be read from any surface. " + (($errArr | ForEach-Object {
            $h = if ($_.hint) { " ($($_.hint))" } else { '' }
            "[$($_.surface)] $($_.error)$h"
        }) -join '  |  ')
    }
    return $payload
}

# ===========================================================================
# THE SCHEDULER JOB -- 'active-assignments-snapshot'
# ===========================================================================
function Invoke-PimActiveAssignmentsSnapshotJob {
    <#
      Run the live read once and persist it as pim.TenantCache kind 'active-assignments':
        { refreshedUtc; rows; counts; surfaceErrors; partial; ok; error; durationMs; source; correlationId }
      Returns the scheduler's handler result shape ({ ran; whatIf; detail; ... }).

      🔒 -WhatIf reads NOTHING and writes NOTHING -- not even a token mint: the whole value of a dry run on this
         job is that it costs nothing.
      🔒 No SQL store -> REFUSED (unimplemented), never a memory-only write. A snapshot kept in the scheduler's
         own process is one the Manager -- another process, usually another container -- can never read, so
         reporting it as written would be the BUG-134 conflation ("a step that cannot work reports success").
      🔴 A read where EVERY surface failed is STILL WRITTEN (the Revoke tab must show the actionable permission
         hint rather than a stale "all good"), and the job then THROWS so the run is recorded failed and the
         engine-failure alert can fire. A PARTIAL read is written and reported ran=$true with the failed surfaces
         named in the detail.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $type = $script:PimActiveAssignmentsSnapshotJobType
    $kind = $script:PimActiveAssignmentsSnapshotCacheKind
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; whatIf = $true
            detail = "whatif:$type -- would read Entra-role / Azure-RBAC / PIM-for-Groups active assignments and write pim.TenantCache/$kind (nothing read, nothing written)" }
    }
    if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type (tools/pim-manager/_tenantSync.ps1 is not loaded on this worker -- no tenant-cache store to write to)" }
    }
    if (-not (Get-PimTenantCacheStoreCs)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type -- no SQL store in this process, so the snapshot could only live in memory where the Manager can never read it (this is 'cannot answer', not 'nothing to do')" }
    }

    $snap = Invoke-PimActiveAssignmentsSnapshot -Fresh
    $errs = @($snap.surfaceErrors)
    $entry = [ordered]@{
        refreshedUtc  = "$($snap.refreshedUtc)"
        rows          = @($snap.rows)
        counts        = $snap.counts
        surfaceErrors = $errs
        partial       = [bool]$snap.partial
        ok            = [bool]$snap.ok
        error         = $(if ($snap.Contains('error')) { "$($snap.error)" } else { '' })
        durationMs    = [int64]$snap.durationMs
        source        = 'scheduler'
        correlationId = "$($global:PIM_JobCorrelationId)"
    }
    $where = Set-PimTenantCacheEntry -Kind $kind -Value $entry
    $c = $snap.counts
    $sum = "{0} total ({1} entra-role, {2} azure-rbac, {3} pim-for-groups) in {4}s -> {5}" -f $c.total, $c['entra-role'], $c['azure-rbac'], $c['pim-for-groups'], $snap.elapsedSec, $where
    if (-not $snap.ok) {
        throw ("[$type] active assignments could not be read from any surface; the failure was stored so the Revoke tab shows it. " + "$($entry.error)")
    }
    $partialTxt = if ($errs.Count) { " PARTIAL -- could not read: " + (@($errs | ForEach-Object { "$($_.surface)" }) -join ', ') } else { '' }
    return [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$c.total; partial = [bool]$snap.partial
        detail = "$type`: $sum$partialTxt" }
}

function Register-PimActiveAssignmentsSnapshotHandler {
    # Called ONLY by tools/pim-scheduler/Start-PimScheduler.ps1. The default handler registered by
    # Initialize-PimDefaultJobHandlers declares the job unimplemented, so a process that never calls this --
    # the Manager above all -- cannot run the live read through "Run now" or any other dispatch.
    if (-not (Get-Command Register-PimJobHandler -ErrorAction SilentlyContinue)) {
        throw 'Register-PimActiveAssignmentsSnapshotHandler: PIM-Scheduler.ps1 is not loaded (Register-PimJobHandler missing).'
    }
    Register-PimJobHandler -Type $script:PimActiveAssignmentsSnapshotJobType -Handler {
        param($job, $now, $whatIf)
        Invoke-PimActiveAssignmentsSnapshotJob -Job $job -NowUtc $now -WhatIf:$whatIf
    }
}

# ===========================================================================
# THE MANAGER'S SIDE -- read the stored snapshot, ask for a refresh. No Graph, no ARM.
# ===========================================================================
function Request-PimActiveAssignmentsSnapshotRefresh {
    # Queue an on-demand 'active-assignments-snapshot' run for the scheduler (pim.Settings SchedulerTriggers).
    # Deduped by type+scope inside Add-PimJobTrigger, so a page that asks repeatedly does not pile up runs.
    # Returns @{ queued; error }. Never throws: failing to queue is reported, and the caller still serves.
    param([string]$Reason = 'manager')
    if (-not (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ queued = $false; error = 'the scheduler trigger queue (PIM-Scheduler.ps1) is not loaded in this process' }
    }
    try {
        [void](Add-PimJobTrigger -Type $script:PimActiveAssignmentsSnapshotJobType -Scope 'All' -Reason $Reason)
        return [pscustomobject]@{ queued = $true; error = '' }
    } catch {
        return [pscustomobject]@{ queued = $false; error = "$($_.Exception.Message)" }
    }
}

function ConvertTo-PimActiveAssignmentsIsoStamp {
    # 🪤 pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime], and "$([datetime])" then renders in the
    # CURRENT CULTURE ("09/13/2026 10:00:00") -- which the GUI's "as of HH:MM" parser cannot read. 5.1 keeps the
    # string. Normalise both to 'yyyy-MM-ddTHH:mm:ssZ'.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    return $s
}

function ConvertTo-PimActiveAssignmentsSnapshotView {
    <#
      PURE. Shape a stored snapshot (or $null) into the GET /api/active-assignments response. Keeps every field
      the GUI already reads -- ok, rows, loadedUtc, counts, surfaceErrors, cacheHit -- and adds the "as of"
      facts: refreshedUtc, ageSeconds, cadenceMinutes, stale, snapshotMissing, refreshQueued, hint.
    #>
    param(
        [AllowNull()][object]$Entry,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$CadenceMinutes = 0,
        [bool]$RefreshQueued = $false,
        [string]$QueueError = ''
    )
    if ($CadenceMinutes -le 0) { $CadenceMinutes = $script:PimActiveAssignmentsSnapshotDefaultCadenceMinutes }
    $now = $NowUtc.ToUniversalTime()
    $refreshedIso = if ($null -ne $Entry) { ConvertTo-PimActiveAssignmentsIsoStamp -Value $Entry.refreshedUtc } else { $null }
    $hasEntry = ($null -ne $Entry) -and ("$refreshedIso".Trim() -ne '')
    if (-not $hasEntry) {
        $hint = if ($RefreshQueued) { 'No snapshot yet -- queued. The scheduler builds it within ~5 min; this page does not wait for it.' }
                else { "No snapshot yet, and a refresh could NOT be queued ($QueueError). The scheduler job 'active-assignments-snapshot' builds it on its cadence." }
        return [ordered]@{
            ok              = $true
            rows            = @()
            counts          = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
            surfaceErrors   = @()
            partial         = $false
            loadedUtc       = $null
            refreshedUtc    = $null
            ageSeconds      = $null
            cacheHit        = $false
            snapshot        = $true
            snapshotMissing = $true
            refreshQueued   = [bool]$RefreshQueued
            cadenceMinutes  = $CadenceMinutes
            stale           = $false
            hint            = $hint
            source          = 'scheduler-snapshot'
        }
    }
    $refreshed = $null
    if (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) { $refreshed = Get-PimUtcStamp $refreshedIso }
    else { try { $refreshed = [datetime]::Parse($refreshedIso, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $refreshed = $null } }
    $age = if ($refreshed) { [int64][math]::Max(0, [math]::Round(($now - $refreshed).TotalSeconds, 0)) } else { $null }
    # Stale = older than two cadences: one missed run is normal (a long tick), two is a scheduler that is not running it.
    $stale = ($null -ne $age) -and ($age -gt (2 * $CadenceMinutes * 60))
    $errs = @(@($Entry.surfaceErrors) | Where-Object { $null -ne $_ })
    $rows = @(@($Entry.rows) | Where-Object { $null -ne $_ })
    $counts = $Entry.counts
    if ($null -eq $counts) {
        $counts = [ordered]@{ total = $rows.Count
            'entra-role' = @($rows | Where-Object { "$($_.type)" -eq 'entra-role' }).Count
            'azure-rbac' = @($rows | Where-Object { "$($_.type)" -eq 'azure-rbac' }).Count
            'pim-for-groups' = @($rows | Where-Object { "$($_.type)" -eq 'pim-for-groups' }).Count }
    }
    $asOf = if ($refreshed) { $refreshed.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { "$refreshedIso" }
    $hint = "as of $asOf (the scheduler refreshes it every $CadenceMinutes min)"
    if ($RefreshQueued) { $hint += '; a refresh is queued -- the scheduler picks it up within ~5 min' }
    elseif ("$QueueError".Trim()) { $hint += "; a refresh could NOT be queued ($QueueError)" }
    if ($stale) { $hint += "; STALE -- older than two cadences, check the 'active-assignments-snapshot' job on the Jobs page" }
    # A stored all-surfaces-failed read stays ok=$false so the Revoke tab shows the actionable error.
    $storedOk = $null
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains('ok')) { $storedOk = [bool]$Entry['ok'] } }
    elseif ($Entry.PSObject.Properties['ok']) { $storedOk = [bool]$Entry.ok }
    if ($null -eq $storedOk) { $storedOk = -not ($rows.Count -eq 0 -and $errs.Count -gt 0) }
    $view = [ordered]@{
        ok              = [bool]$storedOk
        rows           = $rows
        counts          = $counts
        surfaceErrors   = $errs
        partial         = [bool]$Entry.partial
        loadedUtc       = $refreshedIso
        refreshedUtc    = $refreshedIso
        ageSeconds      = $age
        cacheHit        = $true
        snapshot        = $true
        snapshotMissing = $false
        refreshQueued   = [bool]$RefreshQueued
        cadenceMinutes  = $CadenceMinutes
        stale           = [bool]$stale
        durationMs      = $Entry.durationMs
        hint            = $hint
        source          = 'scheduler-snapshot'
    }
    if ("$($Entry.error)".Trim()) { $view['error'] = "$($Entry.error)" }
    return $view
}
