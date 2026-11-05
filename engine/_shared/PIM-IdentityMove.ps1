#Requires -Version 5.1
<#
.SYNOPSIS
    NAM-03 / framework 12.11c item 3 + CR8 (owner 2026-11-04, CRITICAL): the identity MOVER. For ONE install, each PIM app /
    job moves off its system-assigned identity and off the shared user-assigned id-pim-<token> to its own user-assigned
    id-pim-<role>, with the SAME rights, PROVEN, and only then are the old identity's copied rights removed.

.DESCRIPTION
    Built on the pure planning code in PIM-IdentitySplit.ps1 (Get-PimIdentityRoleOf, Get-PimIdentityRightsToCopy). REST only,
    through two seams (no modules, no az CLI):
      -Arm   { param($Method, $Path, $Body) }   Path is ARM-relative WITH api-version (or a full nextLink URL)
      -Graph { param($Method, $Path, $Body) }   Path is Graph v1.0-relative (or a full @odata.nextLink URL)
    A GET of an absent object may throw (404) or return $null -- both read as "absent".

    PLAN (read-only, Get-PimIdentityMovePlan): per role and per app / job of the role: the current identities (system /
    user-assigned id-pim-*; a user-assigned identity NOT named id-pim-* is listed as ignored and never touched), the target
    id-pim-<role>, whether it exists, and the rights to copy:
      graph     Microsoft Graph (and any other API's) application roles of the source principal(s)
      groups    memberships of PIM's OWN groups only (grp-pim-* or a name passed in -PimGroupNames)
      dirRoles  Entra directory role assignments of the source principal(s)
      azure     Azure role assignments held DIRECTLY by the source principal(s) at every scope readable from the
                subscription (assignedTo: the subscription, its resources, and the scopes above it -- root included), plus
                -ExtraScopes (e.g. a registry outside the subscription); Key Vault RBAC and AcrPull are among these
      kv        Key Vault access policies on the vaults of the resource group
      sql       the contained database user (made by the in-network database job ca-pim-dbinit / caj-pim-dbinit)
      settings  what names the identity on the container: the registry pull identity, Key Vault secret references,
                PIM_ManagedIdentityClientId and every env value equal to a source client id (SIGNIN_* / *_CLIENT_ID ...)
    A right at the TENANT ROOT where the Support app has no root User Access Administrator is a CUSTOMER STEP (the exact
    command is in the plan); the role does not switch until the customer step reads back (no gap).

    APPLY (Invoke-PimIdentityMoveRole): per role, in order, each step idempotent and READ BACK before the next:
      1 identity  ensure id-pim-<role> (tag pim-component=<role>)
      2 graph     app roles, PIM group memberships, directory roles
      3 azure     every Azure role assignment (deterministic assignment name: a re-run writes nothing new)
      4 kv        access policies (Key Vault RBAC + AcrPull ride step 3)
      5 sql       the contained user through the database job (-DbInit seam); job missing = STOP, named
      6 switch    attach the identity to the app / job and switch the settings that name the identity
      7 prove     app: the new revision healthy and running as the new client id; job: one execution Succeeded after the
                  switch (started by the mover for the roles in -StartJobRoles, default engine; else the next scheduled run)
      8 cleanup   ONLY after the proof: the old identity's COPIED rights removed (system-assigned: the identity stays
                  enabled, its rights are stripped; shared user-assigned: detached from this app, its rights removed only when
                  no PIM app / job and no SQL server / storage account in the group still uses it). Root rights without root
                  access: a customer step. The old database user is kept (listed).
    A failure at any step = STOP: the record lists everything created / changed in order with the exact undo command;
    nothing old is removed before the proof. -DryRun (= -WhatIf) writes nothing and says what it would do.

      Get-PimIdentityMovePlan          read-only plan of one install
      Invoke-PimIdentityMoveRole       apply one role (steps 1-8); returns the record
      Format-PimIdentityMoveTable      the per-role output table
      Set-PimIdentityMoveSwitch        the container read-modify-write (also the undo of a switch)
#>

if (-not (Get-Command Get-PimIdentityRoleOf -ErrorAction SilentlyContinue)) {
    $__pimIdSplit = Join-Path $PSScriptRoot 'PIM-IdentitySplit.ps1'
    if (Test-Path -LiteralPath $__pimIdSplit) { . $__pimIdSplit }
}

function Get-PimIdentityMoveApi {
    <# PURE. The ARM api-versions the mover uses (a literal: child-scope safe). #>
    return @{ aca = '2024-03-01'; msi = '2023-01-31'; auth = '2022-04-01'; kv = '2023-07-01'; rg = '2021-04-01'; sql = '2021-11-01'; st = '2023-01-01' }
}

function Get-PimIdentityMoveField {
    <# PURE. A field of a hashtable or an object ($null when absent). #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimIdentityMoveMapPairs {
    <# PURE. The key/value pairs of a hashtable or an object (ARM userAssignedIdentities). #>
    param([AllowNull()][object]$Map)
    if ($null -eq $Map) { return @() }
    if ($Map -is [System.Collections.IDictionary]) { return @($Map.Keys | ForEach-Object { @{ key = "$_"; value = $Map[$_] } }) }
    return @($Map.PSObject.Properties | ForEach-Object { @{ key = "$($_.Name)"; value = $_.Value } })
}

function New-PimIdentityMoveGuid {
    <# PURE. A deterministic GUID from a seed (the role assignment name): the same right always gets the same name. #>
    param([Parameter(Mandatory)][string]$Seed)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $b = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Seed.ToLowerInvariant())) } finally { $md5.Dispose() }
    $b[6] = ($b[6] -band 0x0f) -bor 0x30; $b[8] = ($b[8] -band 0x3f) -bor 0x80
    $h = -join @($b | ForEach-Object { $_.ToString("x2") })   # RFC byte order; never a Guid ctor (PS 7 picks the ReadOnlySpan overload: "Argument types do not match")
    return ($h.Substring(0, 8) + "-" + $h.Substring(8, 4) + "-" + $h.Substring(12, 4) + "-" + $h.Substring(16, 4) + "-" + $h.Substring(20, 12))
}

function Test-PimIdentityMoveRootScope {
    <# PURE. Is the scope the tenant root ('/' or the tenant root management group)? #>
    param([AllowEmptyString()][string]$Scope, [AllowEmptyString()][string]$TenantId = '')
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant()
    if ($s -eq '') { return $true }
    if ($TenantId -and $s -eq ('/providers/microsoft.management/managementgroups/' + "$TenantId".Trim().ToLowerInvariant())) { return $true }
    return $false
}

function Test-PimIdentityMovePimIdentityName {
    <# PURE. A PIM-defined user-assigned identity: id-pim-<word>[-<word>]. Anything else is never touched. #>
    param([AllowEmptyString()][string]$Name)
    return ("$Name".Trim() -match '^(?i)id-pim-[a-z0-9]+(-[a-z0-9]+)*$')
}

function Test-PimIdentityMovePimGroup {
    <# PURE. A PIM-defined group: grp-pim-* or one of the names passed (-PimGroupNames). #>
    param([AllowEmptyString()][string]$DisplayName, [AllowEmptyCollection()][string[]]$PimGroupNames = @())
    $n = "$DisplayName".Trim()
    if (-not $n) { return $false }
    if ($n -match '^(?i)grp-pim-') { return $true }
    return [bool](@($PimGroupNames | Where-Object { "$_".Trim() -and "$_".Trim() -ieq $n }).Count)
}

function Get-PimIdentityMoveSqlRoles {
    <# PURE. The database roles of the role's contained user: -Override wins, else the access catalog (PIM-SqlAccess.ps1). #>
    param([Parameter(Mandatory)][string]$Role, [hashtable]$Override = @{})
    if ($Override -and $Override.ContainsKey($Role)) { return @($Override[$Role]) }
    $comp = switch ($Role) { 'web' { 'web' } 'updater' { 'updater' } 'asbuilt' { 'asbuilt' } 'publish' { 'publish' } 'downlink' { 'downlink' } default { 'engine' } }
    if (Get-Command Get-PimSqlComponentAccess -ErrorAction SilentlyContinue) { return @((Get-PimSqlComponentAccess -Component $comp).roles) }
    switch ($comp) {
        'web' { return @('pim_web') } 'updater' { return @('pim_updater', 'db_ddladmin') } 'asbuilt' { return @('pim_asbuilt') }
        'publish' { return @('pim_publish') } 'downlink' { return @('pim_downlink', 'pim_engine') } default { return @('pim_engine') }
    }
}

function Get-PimIdentityMoveNoSqlRoles { <# PURE. Roles with NO contained user of their own (dbinit signs in as the SQL admin group member). #> return @('dbinit') }
function Get-PimIdentityMoveDefaultStartJobRoles { <# PURE. Roles whose job the mover may START for the proof (one tick). #> return @('engine') }

# ---------------------------------------------------------------------------------------------------------- REST helpers
function Invoke-PimIdentityMoveGet {
    <# A GET through a seam; an absent object (404 / NotFound thrown, or $null) -> $null. Any other error throws. #>
    param([Parameter(Mandatory)][scriptblock]$Seam, [Parameter(Mandatory)][string]$Path)
    try { return (& $Seam 'GET' $Path $null) } catch {
        if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|does not exist|Request_ResourceNotFound') { return $null }
        throw
    }
}

function Get-PimIdentityMoveList {
    <# A list GET through a seam: .value unwrapped, nextLink / @odata.nextLink followed. Absent -> empty. #>
    param([Parameter(Mandatory)][scriptblock]$Seam, [Parameter(Mandatory)][string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $next = $Path; $guard = 0
    while ($next -and $guard -lt 50) {
        $guard++
        $r = Invoke-PimIdentityMoveGet -Seam $Seam -Path $next
        $next = $null
        if ($null -eq $r) { break }
        $hasValue = if ($r -is [System.Collections.IDictionary]) { $r.Contains('value') } elseif ($r -is [System.Array]) { $false } else { [bool]$r.PSObject.Properties['value'] }
        if ($hasValue) { $vv = if ($r -is [System.Collections.IDictionary]) { $r['value'] } else { $r.value }; foreach ($x in @($vv)) { if ($null -ne $x) { $out.Add($x) } } }
        elseif ($r -is [System.Array]) { foreach ($x in $r) { if ($null -ne $x) { $out.Add($x) } } }
        else { $out.Add($r) }
        $nl = Get-PimIdentityMoveField $r '@odata.nextLink'; if (-not $nl) { $nl = Get-PimIdentityMoveField $r 'nextLink' }
        if ($nl) { $next = "$nl" }
    }
    return @($out.ToArray())
}

# ---------------------------------------------------------------------------------------------------------- reads
function Read-PimIdentityMoveInstall {
    <# READ. The install's apps, jobs, user-assigned identities, vaults, SQL servers and storage accounts (resource group). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $api = Get-PimIdentityMoveApi
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $rgObj = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$rg`?api-version=$($api.rg)"
    return @{
        rgId       = $rg
        location   = "$(Get-PimIdentityMoveField $rgObj 'location')"
        apps       = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/containerApps?api-version=$($api.aca)")
        jobs       = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/jobs?api-version=$($api.aca)")
        identities = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=$($api.msi)")
        vaults     = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.KeyVault/vaults?api-version=$($api.kv)")
        sqlServers = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.Sql/servers?api-version=$($api.sql)")
        storage    = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.Storage/storageAccounts?api-version=$($api.st)")
    }
}

function Get-PimIdentityMoveSources {
    <#
      PURE. The identities an app / job holds today that the move takes it OFF: its system-assigned identity (when enabled) and
      every attached user-assigned identity named id-pim-* that is not the target and not another role's id-pim-<role>.
      A user-assigned identity NOT named id-pim-* is returned in .ignored (never touched).
    #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)][string]$Target, [AllowEmptyCollection()][object[]]$Identities = @())
    $byId = @{}
    foreach ($u in @($Identities | Where-Object { $_ })) { $byId["$(Get-PimIdentityMoveField $u 'id')".ToLowerInvariant()] = $u }
    $ident = Get-PimIdentityMoveField $Resource 'identity'
    $src = New-Object System.Collections.Generic.List[object]; $ign = New-Object System.Collections.Generic.List[string]
    $sysPid = "$(Get-PimIdentityMoveField $ident 'principalId')".Trim()
    if ($sysPid -and "$(Get-PimIdentityMoveField $ident 'type')" -match '(?i)SystemAssigned') {
        $src.Add(@{ kind = 'system'; name = "$(Get-PimIdentityMoveField $Resource 'name') (system-assigned)"; id = 'system'; principalId = $sysPid; clientId = '' })
    }
    $stdTargets = @('web', 'engine', 'updater', 'downlink', 'publish', 'requests', 'mcp', 'dbinit', 'asbuilt') | ForEach-Object { "id-pim-$_" }
    foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimIdentityMoveField $ident 'userAssignedIdentities'))) {
        $id = "$($pair.key)"; $leaf = @($id -split '/' | Where-Object { $_ })[-1]
        $u = $byId[$id.ToLowerInvariant()]
        $pid0 = "$(Get-PimIdentityMoveField $pair.value 'principalId')"; $cid0 = "$(Get-PimIdentityMoveField $pair.value 'clientId')"
        if ($u) { $up = Get-PimIdentityMoveField $u 'properties'; if (-not $pid0) { $pid0 = "$(Get-PimIdentityMoveField $up 'principalId')" }; if (-not $cid0) { $cid0 = "$(Get-PimIdentityMoveField $up 'clientId')" } }
        if (-not (Test-PimIdentityMovePimIdentityName -Name $leaf)) { $ign.Add($leaf); continue }
        if ($leaf -ieq $Target -or ($stdTargets -contains $leaf.ToLowerInvariant())) { continue }
        $src.Add(@{ kind = 'user'; name = $leaf; id = $id; principalId = $pid0; clientId = $cid0 })
    }
    return @{ sources = @($src.ToArray()); ignored = @($ign.ToArray()) }
}

function Read-PimIdentityMoveRights {
    <#
      READ. The rights ONE principal holds: azure (held directly: properties.principalId = the principal), graph app roles,
      PIM group memberships (only PIM groups), directory roles, Key Vault access policies on -Vaults.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [AllowEmptyString()][string]$PrincipalId, [AllowEmptyString()][string]$TenantId = '', [AllowEmptyCollection()][object[]]$Vaults = @(),
          [AllowEmptyCollection()][string[]]$ExtraScopes = @(), [AllowEmptyCollection()][string[]]$PimGroupNames = @())
    $api = Get-PimIdentityMoveApi
    $out = @{ azure = @(); graph = @(); groups = @(); dirRoles = @(); kv = @() }
    $p = "$PrincipalId".Trim()
    if (-not $p) { return $out }
    $seen = @{}; $az = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @("/subscriptions/$SubscriptionId") + @($ExtraScopes | Where-Object { "$_".Trim() })) {
        $s = "$scope".Trim().TrimEnd('/')
        foreach ($a in @(Get-PimIdentityMoveList -Seam $Arm -Path "$s/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('$p')&api-version=$($api.auth)")) {
            $pr = Get-PimIdentityMoveField $a 'properties'
            if ("$(Get-PimIdentityMoveField $pr 'principalId')" -ine $p) { continue }   # via a group: not this principal's own right
            $id = "$(Get-PimIdentityMoveField $a 'id')"; if ($seen.ContainsKey($id.ToLowerInvariant())) { continue }; $seen[$id.ToLowerInvariant()] = $true
            $sc = "$(Get-PimIdentityMoveField $pr 'scope')"
            $az.Add([pscustomobject]@{ id = $id; roleDefinitionId = "$(Get-PimIdentityMoveField $pr 'roleDefinitionId')"; scope = $sc; root = (Test-PimIdentityMoveRootScope -Scope $sc -TenantId $TenantId) })
        }
    }
    $out.azure = @($az.ToArray())
    $out.graph = @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$p/appRoleAssignments" | ForEach-Object {
        [pscustomobject]@{ id = "$(Get-PimIdentityMoveField $_ 'id')"; resourceId = "$(Get-PimIdentityMoveField $_ 'resourceId')"; appRoleId = "$(Get-PimIdentityMoveField $_ 'appRoleId')"; resourceDisplayName = "$(Get-PimIdentityMoveField $_ 'resourceDisplayName')" } })
    $out.groups = @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$p/memberOf/microsoft.graph.group?`$select=id,displayName" |
        Where-Object { Test-PimIdentityMovePimGroup -DisplayName "$(Get-PimIdentityMoveField $_ 'displayName')" -PimGroupNames $PimGroupNames } |
        ForEach-Object { [pscustomobject]@{ id = "$(Get-PimIdentityMoveField $_ 'id')"; displayName = "$(Get-PimIdentityMoveField $_ 'displayName')" } })
    $out.dirRoles = @(Get-PimIdentityMoveList -Seam $Graph -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$p'" |
        Where-Object { "$(Get-PimIdentityMoveField $_ 'principalId')" -ieq $p -or -not "$(Get-PimIdentityMoveField $_ 'principalId')" } |
        ForEach-Object { [pscustomobject]@{ id = "$(Get-PimIdentityMoveField $_ 'id')"; roleDefinitionId = "$(Get-PimIdentityMoveField $_ 'roleDefinitionId')"; directoryScopeId = "$(Get-PimIdentityMoveField $_ 'directoryScopeId')" } })
    $kv = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($Vaults | Where-Object { $_ })) {
        foreach ($ap in @((Get-PimIdentityMoveField (Get-PimIdentityMoveField $v 'properties') 'accessPolicies'))) {
            if ($ap -and "$(Get-PimIdentityMoveField $ap 'objectId')" -ieq $p) {
                $kv.Add([pscustomobject]@{ vaultId = "$(Get-PimIdentityMoveField $v 'id')"; vaultName = "$(Get-PimIdentityMoveField $v 'name')"; tenantId = "$(Get-PimIdentityMoveField $ap 'tenantId')"; permissions = (Get-PimIdentityMoveField $ap 'permissions') })
            }
        }
    }
    $out.kv = @($kv.ToArray())
    return $out
}

function Get-PimIdentityMoveKvMissing {
    <# PURE. Key Vault access policies of the sources the target does not fully hold (per vault, merged permissions). #>
    param([AllowEmptyCollection()][object[]]$Source = @(), [AllowEmptyCollection()][object[]]$Target = @())
    $kinds = @('keys', 'secrets', 'certificates', 'storage')
    $merge = @{}
    foreach ($s in @($Source | Where-Object { $_ })) {
        $k = "$($s.vaultId)".ToLowerInvariant()
        if (-not $merge.ContainsKey($k)) { $merge[$k] = @{ vaultId = "$($s.vaultId)"; vaultName = "$($s.vaultName)"; tenantId = "$($s.tenantId)"; permissions = @{} } }
        foreach ($kd in $kinds) { $pv = @(Get-PimIdentityMoveField $s.permissions $kd | Where-Object { "$_".Trim() }); if ($pv.Count) { if (-not $merge[$k].permissions.ContainsKey($kd)) { $merge[$k].permissions[$kd] = @() }; $merge[$k].permissions[$kd] = @(@($merge[$k].permissions[$kd]) + $pv | ForEach-Object { "$_".ToLowerInvariant() } | Select-Object -Unique) } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $merge.Keys) {
        $have = @{}
        foreach ($t in @($Target | Where-Object { $_ -and "$($_.vaultId)".ToLowerInvariant() -eq $k })) { foreach ($kd in $kinds) { foreach ($pv in @(Get-PimIdentityMoveField $t.permissions $kd)) { if ("$pv".Trim()) { $have["$kd|$("$pv".ToLowerInvariant())"] = $true } } } }
        $miss = $false
        foreach ($kd in $kinds) { if (-not $merge[$k].permissions.ContainsKey($kd)) { continue }; foreach ($pv in @($merge[$k].permissions[$kd]) | Where-Object { "$_".Trim() }) { if (-not $have.ContainsKey("$kd|$pv")) { $miss = $true } } }
        if ($miss) { $out.Add([pscustomobject]$merge[$k]) }
    }
    return @($out.ToArray())
}

function Get-PimIdentityMoveDirRolesMissing {
    <# PURE. Directory role assignments of the sources the target does not hold (role + scope). #>
    param([AllowEmptyCollection()][object[]]$Source = @(), [AllowEmptyCollection()][object[]]$Target = @())
    $k = { param($a) "$($a.roleDefinitionId)".ToLowerInvariant() + '|' + "$($a.directoryScopeId)".ToLowerInvariant() }
    $have = @{}; foreach ($t in @($Target | Where-Object { $_ })) { $have[(& $k $t)] = $true }
    $seen = @{}
    return @(foreach ($s in @($Source | Where-Object { $_ })) { $kk = & $k $s; if (-not $have.ContainsKey($kk) -and -not $seen.ContainsKey($kk)) { $seen[$kk] = $true; $s } })
}

function Get-PimIdentityMoveCustomerCommand {
    <# PURE. The exact command a customer's Owner / User Access Administrator at the tenant root runs (Cloud Shell). #>
    param([Parameter(Mandatory)][ValidateSet('add', 'remove')][string]$Action, [AllowEmptyString()][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefinitionId, [Parameter(Mandatory)][string]$Scope, [string]$PrincipalName = '')
    $rg = @("$RoleDefinitionId" -split '/' | Where-Object { $_ })[-1]
    $who = if ("$PrincipalId".Trim()) { "$PrincipalId".Trim() } else { "<object id of $PrincipalName>" }
    $sc = if ("$Scope".Trim().TrimEnd('/')) { "$Scope".Trim().TrimEnd('/') } else { '/' }
    if ($Action -eq 'add') { return "az role assignment create --assignee-object-id $who --assignee-principal-type ServicePrincipal --role $rg --scope $sc" }
    return "az role assignment delete --assignee $who --role $rg --scope $sc"
}

# ---------------------------------------------------------------------------------------------------------- the plan
function Get-PimIdentityMovePlan {
    <#
      READ-ONLY. The plan of ONE install: one entry per role (the resources of the role, their sources, the target, the rights
      the target still needs, the customer steps, the database user, the settings that name the identity).
      -SupportHasRootAccess: the Support app holds User Access Administrator at the tenant root of THIS install (the NAM-03 item
      lists which installs do). Default: NO -- every root right is a customer step.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [AllowEmptyString()][string]$TenantId = '',
          [switch]$SupportHasRootAccess, [AllowEmptyCollection()][string[]]$ExtraScopes = @(), [AllowEmptyCollection()][string[]]$PimGroupNames = @(),
          [hashtable]$SqlRoles = @{}, [AllowNull()][object]$Install = $null)
    $inst = if ($Install) { $Install } else { Read-PimIdentityMoveInstall -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup }
    $byName = @{}; foreach ($u in @($inst.identities | Where-Object { $_ })) { $byName["$(Get-PimIdentityMoveField $u 'name')".ToLowerInvariant()] = $u }
    $all = @(@($inst.apps | Where-Object { $_ } | ForEach-Object { @{ o = $_; kind = 'app' } }) + @($inst.jobs | Where-Object { $_ } | ForEach-Object { @{ o = $_; kind = 'job' } }))
    $dbJob = @($inst.jobs | Where-Object { $_ -and (Get-PimIdentityRoleOf -Name "$(Get-PimIdentityMoveField $_ 'name')") -eq 'dbinit' }) | Select-Object -First 1
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($x in $all) {
        $o = $x.o; $name = "$(Get-PimIdentityMoveField $o 'name')"; $role = Get-PimIdentityRoleOf -Name $name
        if (-not $role) { continue }
        $target = "id-pim-$role"
        $s = Get-PimIdentityMoveSources -Resource $o -Target $target -Identities $inst.identities
        $tgt = $byName[$target]; $tp = Get-PimIdentityMoveField $tgt 'properties'
        $tid = if ($tgt) { "$(Get-PimIdentityMoveField $tgt 'id')" } else { '' }
        $attached = $false
        if ($tid) { foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimIdentityMoveField (Get-PimIdentityMoveField $o 'identity') 'userAssignedIdentities'))) { if ($pair.key -ieq $tid) { $attached = $true } } }
        $cid = ''
        foreach ($c in @((Get-PimIdentityMoveField (Get-PimIdentityMoveField (Get-PimIdentityMoveField $o 'properties') 'template') 'containers'))) {
            if (-not $c -or "$(Get-PimIdentityMoveField $c 'name')" -eq 'signin-front') { continue }
            foreach ($e in @(Get-PimIdentityMoveField $c 'env')) { if ($e -and "$(Get-PimIdentityMoveField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimIdentityMoveField $e 'value')".Trim()) { $cid = "$(Get-PimIdentityMoveField $e 'value')".Trim() } }
        }
        $signsInAsTarget = [bool]($tgt -and $attached -and $cid -and $cid -ieq "$(Get-PimIdentityMoveField $tp 'clientId')")
        $rows.Add([pscustomobject]@{
            role = $role; resource = $name; resourceId = "$(Get-PimIdentityMoveField $o 'id')"; kind = $x.kind; location = "$(Get-PimIdentityMoveField $o 'location')"
            target = $target; targetExists = [bool]$tgt; targetId = $tid; targetClientId = "$(Get-PimIdentityMoveField $tp 'clientId')"; targetPrincipalId = "$(Get-PimIdentityMoveField $tp 'principalId')"
            targetAttached = $attached; signsInAsTarget = $signsInAsTarget; currentClientId = $cid
            sources = @($s.sources); ignored = @($s.ignored)
            settings = @(Get-PimIdentityMoveSettingsToSwitch -Resource $o -Sources @($s.sources))
        })
    }
    $roles = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($rows.ToArray() | Group-Object role)) {
        $rr = @($g.Group); $role = "$($g.Name)"; $first = $rr[0]; $target = "$($first.target)"
        $srcU = @{}; foreach ($r in $rr) { foreach ($s in @($r.sources)) { if ($s.principalId) { $srcU["$($s.principalId)".ToLowerInvariant()] = $s } } }
        $sources = @($srcU.Values)
        $sr = @{ azure = @(); graph = @(); groups = @(); dirRoles = @(); kv = @() }
        $perSource = @{}
        foreach ($s in $sources) {
            $r = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -PrincipalId $s.principalId -TenantId $TenantId -Vaults $inst.vaults -ExtraScopes $ExtraScopes -PimGroupNames $PimGroupNames
            $perSource["$($s.principalId)".ToLowerInvariant()] = $r
            foreach ($k in @('azure', 'graph', 'groups', 'dirRoles', 'kv')) { $sr[$k] = @(@($sr[$k]) + @($r[$k])) }
        }
        $tr = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -PrincipalId $first.targetPrincipalId -TenantId $TenantId -Vaults $inst.vaults -ExtraScopes $ExtraScopes -PimGroupNames $PimGroupNames
        $c = Get-PimIdentityRightsToCopy -SourceAzure $sr.azure -TargetAzure $tr.azure -SourceGraph $sr.graph -TargetGraph $tr.graph `
                -SourceGroups @($sr.groups | ForEach-Object { "$($_.id)" }) -TargetGroups @($tr.groups | ForEach-Object { "$($_.id)" })
        $azRoot = @(@($c.azure) | Where-Object { $_.root }); $azNorm = @(@($c.azure) | Where-Object { -not $_.root })
        $cust = New-Object System.Collections.Generic.List[object]
        if (-not $SupportHasRootAccess) {
            foreach ($a in $azRoot) { $cust.Add([pscustomobject]@{ when = 'before the switch'; what = "grant $target the role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at the tenant root"; command = (Get-PimIdentityMoveCustomerCommand -Action add -PrincipalId $first.targetPrincipalId -PrincipalName $target -RoleDefinitionId $a.roleDefinitionId -Scope $a.scope) }) }
        }
        $grpNames = @{}; foreach ($gq in @($sr.groups)) { $grpNames["$($gq.id)".ToLowerInvariant()] = "$($gq.displayName)" }
        $needsSql = -not ((Get-PimIdentityMoveNoSqlRoles) -contains $role)
        $sqlRolesR = if ($needsSql) { @(Get-PimIdentityMoveSqlRoles -Role $role -Override $SqlRoles) } else { @() }
        # cleanup = every app / job already signs in as the target, but an old identity is still attached (user-assigned) or
        # still holds a right the target holds too (what step 8 removes); nothing left = ok (a re-run writes nothing)
        $removable = [bool](@($sources | Where-Object { $_.kind -eq 'user' }).Count)
        if (-not $removable) {
            foreach ($s in $sources) {
                $ps = $perSource["$($s.principalId)".ToLowerInvariant()]
                $left = Get-PimIdentityRightsToCopy -SourceAzure @($ps.azure | Where-Object { $SupportHasRootAccess -or -not $_.root }) -TargetAzure $tr.azure -SourceGraph $ps.graph -TargetGraph $tr.graph -SourceGroups @($ps.groups | ForEach-Object { "$($_.id)" }) -TargetGroups @($tr.groups | ForEach-Object { "$($_.id)" })
                $heldA = @($ps.azure | Where-Object { $SupportHasRootAccess -or -not $_.root }).Count - @($left.azure).Count
                $heldG = @($ps.graph).Count - @($left.graph).Count; $heldM = @($ps.groups).Count - @($left.groups).Count
                $heldD = @($ps.dirRoles).Count - @(Get-PimIdentityMoveDirRolesMissing -Source $ps.dirRoles -Target $tr.dirRoles).Count
                $heldK = @($ps.kv | Where-Object { -not @(Get-PimIdentityMoveKvMissing -Source @($_) -Target $tr.kv).Count }).Count
                if (($heldA + $heldG + $heldM + $heldD + $heldK) -gt 0) { $removable = $true }
            }
        }
        $state = if (@($rr | Where-Object { -not $_.signsInAsTarget }).Count) { 'move' } elseif ($removable) { 'cleanup' } else { 'ok' }
        $roles.Add([pscustomobject]@{
            role = $role; target = $target; targetExists = $first.targetExists; targetId = $first.targetId; targetClientId = $first.targetClientId; targetPrincipalId = $first.targetPrincipalId
            resources = $rr; sources = $sources; state = $state
            sourceRights = $sr; perSource = $perSource; targetRights = $tr
            toCopy = @{ graph = @($c.graph); groups = @(@($c.groups) | ForEach-Object { [pscustomobject]@{ id = "$_"; displayName = $grpNames["$_".ToLowerInvariant()] } }); dirRoles = @(Get-PimIdentityMoveDirRolesMissing -Source $sr.dirRoles -Target $tr.dirRoles)
                        azure = $(if ($SupportHasRootAccess) { @($c.azure) } else { $azNorm }); azureRootCustomer = $(if ($SupportHasRootAccess) { @() } else { $azRoot }); kv = @(Get-PimIdentityMoveKvMissing -Source $sr.kv -Target $tr.kv) }
            customerSteps = @($cust.ToArray())
            sql = [pscustomobject]@{ needed = $needsSql; user = $target; roles = $sqlRolesR; job = $(if ($dbJob) { "$(Get-PimIdentityMoveField $dbJob 'name')" } else { '' }); jobId = $(if ($dbJob) { "$(Get-PimIdentityMoveField $dbJob 'id')" } else { '' }) }
        })
    }
    return [pscustomobject]@{
        subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroup; tenantId = $TenantId; location = "$($inst.location)"; supportHasRootAccess = [bool]$SupportHasRootAccess
        roles = @($roles.ToArray()); install = $inst; extraScopes = @($ExtraScopes); pimGroupNames = @($PimGroupNames)
    }
}

function Get-PimIdentityMoveSettingsToSwitch {
    <# PURE. What on the container names a source identity: registries, Key Vault secret references, env values. #>
    param([Parameter(Mandatory)][object]$Resource, [AllowEmptyCollection()][object[]]$Sources = @())
    $ids = @{}; $cids = @{}
    foreach ($s in @($Sources)) { $ids["$($s.id)".ToLowerInvariant()] = $s.name; if ("$($s.clientId)".Trim()) { $cids["$($s.clientId)".ToLowerInvariant()] = $s.name } }
    $pr = Get-PimIdentityMoveField $Resource 'properties'; $cfg = Get-PimIdentityMoveField $pr 'configuration'
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-PimIdentityMoveField $cfg 'registries')) { if ($r -and $ids.ContainsKey("$(Get-PimIdentityMoveField $r 'identity')".ToLowerInvariant())) { $out.Add([pscustomobject]@{ where = 'registry'; name = "$(Get-PimIdentityMoveField $r 'server')"; from = "$(Get-PimIdentityMoveField $r 'identity')" }) } }
    foreach ($s in @(Get-PimIdentityMoveField $cfg 'secrets')) { if ($s -and "$(Get-PimIdentityMoveField $s 'keyVaultUrl')".Trim() -and $ids.ContainsKey("$(Get-PimIdentityMoveField $s 'identity')".ToLowerInvariant())) { $out.Add([pscustomobject]@{ where = 'secret'; name = "$(Get-PimIdentityMoveField $s 'name')"; from = "$(Get-PimIdentityMoveField $s 'identity')" }) } }
    foreach ($c in @(Get-PimIdentityMoveField (Get-PimIdentityMoveField $pr 'template') 'containers')) {
        if (-not $c) { continue }
        foreach ($e in @(Get-PimIdentityMoveField $c 'env')) { if ($e -and $cids.ContainsKey("$(Get-PimIdentityMoveField $e 'value')".Trim().ToLowerInvariant())) { $out.Add([pscustomobject]@{ where = 'env'; name = "$(Get-PimIdentityMoveField $c 'name')/$(Get-PimIdentityMoveField $e 'name')"; from = "$(Get-PimIdentityMoveField $e 'value')" }) } }
    }
    return @($out.ToArray())
}

# ---------------------------------------------------------------------------------------------------------- the switch
function Set-PimIdentityMoveSwitch {
    <#
      READ-MODIFY-WRITE of ONE app / job (never a fragment): attach -ToId, and every setting that names a -FromIds identity
      (registry identity, Key Vault secret reference identity, env values equal to -FromClientIds) names -ToId / -ToClientId;
      PIM_ManagedIdentityClientId in every non-signin-front container = -ToClientId (-ToSystem: removed, the system identity
      again -- the undo of a switch). -Detach: user-assigned ids removed from the identity map. Secrets are re-read with
      listSecrets (a GET returns none) only when the configuration is written. READ BACK; throws on a mismatch.
      Returns @{ changed; detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceId,
          [AllowEmptyCollection()][string[]]$FromIds = @(), [AllowEmptyCollection()][string[]]$FromClientIds = @(),
          [AllowEmptyString()][string]$ToId = '', [AllowEmptyString()][string]$ToClientId = '', [switch]$ToSystem,
          [AllowEmptyCollection()][string[]]$Detach = @(), [string[]]$ClientIdEnvNames = @('PIM_ManagedIdentityClientId'), [switch]$DryRun)
    $api = Get-PimIdentityMoveApi
    $path = "$ResourceId`?api-version=$($api.aca)"
    $o = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
    if (-not $o) { throw "$ResourceId not found" }
    $fromSet = @{}; foreach ($f in @($FromIds)) { if ("$f".Trim()) { $fromSet["$f".Trim().ToLowerInvariant()] = $true } }
    $fromC = @{}; foreach ($f in @($FromClientIds)) { if ("$f".Trim()) { $fromC["$f".Trim().ToLowerInvariant()] = $true } }
    $detSet = @{}; foreach ($d in @($Detach)) { if ("$d".Trim()) { $detSet["$d".Trim().ToLowerInvariant()] = $true } }
    $toIdent = if ($ToSystem) { 'system' } else { "$ToId" }
    $changes = New-Object System.Collections.Generic.List[string]
    # identity
    $ident = Get-PimIdentityMoveField $o 'identity'
    $type = "$(Get-PimIdentityMoveField $ident 'type')"
    $hasSys = $type -match '(?i)SystemAssigned'
    $map = [ordered]@{}; $removed = @()
    foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimIdentityMoveField $ident 'userAssignedIdentities'))) {
        if ($detSet.ContainsKey($pair.key.ToLowerInvariant())) { $removed += $pair.key; continue }
        $map[$pair.key] = @{}
    }
    if ("$ToId".Trim() -and -not @($map.Keys | Where-Object { "$_" -ieq $ToId }).Count) { $map[$ToId] = @{}; $changes.Add("attach $(@($ToId -split '/')[-1])") }
    foreach ($r in $removed) { $changes.Add("detach $(@($r -split '/')[-1])") }
    $newType = if ($hasSys -and $map.Count) { 'SystemAssigned,UserAssigned' } elseif ($hasSys) { 'SystemAssigned' } elseif ($map.Count) { 'UserAssigned' } else { 'None' }
    $identBody = @{ type = $newType; userAssignedIdentities = @{} }
    foreach ($k in $map.Keys) { $identBody.userAssignedIdentities[$k] = @{} }
    foreach ($r in $removed) { $identBody.userAssignedIdentities[$r] = $null }
    if (-not $identBody.userAssignedIdentities.Count) { $identBody.Remove('userAssignedIdentities') }
    # configuration
    $pr = Get-PimIdentityMoveField $o 'properties'; $cfg = Get-PimIdentityMoveField $pr 'configuration'
    $cfgChanged = $false
    $regs2 = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(Get-PimIdentityMoveField $cfg 'registries')) {
        if (-not $r) { continue }
        $h = [ordered]@{}
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { $h[$k] = $r[$k] } } else { foreach ($pp in $r.PSObject.Properties) { $h[$pp.Name] = $pp.Value } }
        if ($fromSet.ContainsKey("$($h['identity'])".ToLowerInvariant())) { $h['identity'] = $toIdent; $cfgChanged = $true; $changes.Add("registry $($h['server']) pulls as $(@($toIdent -split '/')[-1])") }
        $regs2.Add([pscustomobject]$h)
    }
    $secNeeds = @(@(Get-PimIdentityMoveField $cfg 'secrets') | Where-Object { $_ -and "$(Get-PimIdentityMoveField $_ 'keyVaultUrl')".Trim() -and $fromSet.ContainsKey("$(Get-PimIdentityMoveField $_ 'identity')".ToLowerInvariant()) })
    $body = @{ identity = $identBody }
    if ($secNeeds.Count) { $cfgChanged = $true; foreach ($s in $secNeeds) { $changes.Add("Key Vault secret reference $(Get-PimIdentityMoveField $s 'name') as $(@($toIdent -split '/')[-1])") } }
    # template
    $tpl = Get-PimIdentityMoveField $pr 'template'
    $tplChanged = $false
    $conts = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-PimIdentityMoveField $tpl 'containers')) {
        if (-not $c) { continue }
        $cn = "$(Get-PimIdentityMoveField $c 'name')"
        $envL = New-Object System.Collections.Generic.List[object]; $had = @{}
        foreach ($e in @(Get-PimIdentityMoveField $c 'env')) {
            if (-not $e) { continue }
            $en = "$(Get-PimIdentityMoveField $e 'name')"; $ev = Get-PimIdentityMoveField $e 'value'; $esr = Get-PimIdentityMoveField $e 'secretRef'
            if (@($ClientIdEnvNames) -contains $en -and $cn -ne 'signin-front') {
                $had[$en] = $true
                if ($ToSystem) { $tplChanged = $true; $changes.Add("$cn/$en removed (system-assigned)"); continue }
                if ("$ev" -ine $ToClientId) { $tplChanged = $true; $changes.Add("$cn/$en = $ToClientId") }
                $envL.Add([pscustomobject]@{ name = $en; value = $ToClientId }); continue
            }
            if (-not "$esr".Trim() -and $fromC.ContainsKey("$ev".Trim().ToLowerInvariant()) -and -not $ToSystem) { $tplChanged = $true; $changes.Add("$cn/$en = $ToClientId"); $envL.Add([pscustomobject]@{ name = $en; value = $ToClientId }); continue }
            $envL.Add($e)
        }
        foreach ($nm in @($ClientIdEnvNames)) {
            if (-not $had.ContainsKey($nm) -and -not $ToSystem -and "$ToClientId".Trim() -and $cn -ne 'signin-front') { $tplChanged = $true; $changes.Add("$cn/$nm = $ToClientId"); $envL.Add([pscustomobject]@{ name = $nm; value = $ToClientId }) }
        }
        $h = [ordered]@{}
        if ($c -is [System.Collections.IDictionary]) { foreach ($k in $c.Keys) { $h[$k] = $c[$k] } } else { foreach ($pp in $c.PSObject.Properties) { $h[$pp.Name] = $pp.Value } }
        $h['env'] = @($envL.ToArray())
        $conts.Add([pscustomobject]$h)
    }
    $identChanged = ($changes | Where-Object { $_ -match '^(attach|detach) ' }).Count -gt 0
    if (-not $changes.Count) { return @{ changed = $false; detail = 'already as asked' } }
    if ($DryRun) { return @{ changed = $true; dryRun = $true; detail = ($changes -join '; ') } }
    $props = @{}
    if ($tplChanged) {
        $tplH = [ordered]@{}
        if ($tpl -is [System.Collections.IDictionary]) { foreach ($k in $tpl.Keys) { $tplH[$k] = $tpl[$k] } } else { foreach ($pp in $tpl.PSObject.Properties) { $tplH[$pp.Name] = $pp.Value } }
        $tplH['containers'] = @($conts.ToArray())
        $props['template'] = [pscustomobject]$tplH
    }
    if ($cfgChanged) {
        # every secret with its value / reference (listSecrets) -- a configuration written without them would DELETE them
        $ls = & $Arm 'POST' "$ResourceId/listSecrets?api-version=$($api.aca)" @{}
        $lsv = @(@(Get-PimIdentityMoveField $ls 'value') | Where-Object { $_ })
        if ($lsv.Count -lt @(@(Get-PimIdentityMoveField $cfg 'secrets') | Where-Object { $_ }).Count) { throw "listSecrets returned $($lsv.Count) secret(s) but $ResourceId declares more -- refusing to write a configuration that would drop secrets" }
        $secs = @($lsv | ForEach-Object {
            $s = [ordered]@{ name = "$(Get-PimIdentityMoveField $_ 'name')" }
            $kvu = "$(Get-PimIdentityMoveField $_ 'keyVaultUrl')"
            if ($kvu.Trim()) { $si = "$(Get-PimIdentityMoveField $_ 'identity')"; if ($fromSet.ContainsKey($si.ToLowerInvariant())) { $si = $toIdent }; $s.keyVaultUrl = $kvu; $s.identity = $si } else { $s.value = "$(Get-PimIdentityMoveField $_ 'value')" }
            [pscustomobject]$s })
        $cfgH = [ordered]@{}
        if ($cfg -is [System.Collections.IDictionary]) { foreach ($k in $cfg.Keys) { $cfgH[$k] = $cfg[$k] } } else { foreach ($pp in $cfg.PSObject.Properties) { $cfgH[$pp.Name] = $pp.Value } }
        $cfgH['registries'] = @($regs2.ToArray()); $cfgH['secrets'] = $secs
        $props['configuration'] = [pscustomobject]$cfgH
    }
    if ($props.Count) { $body['properties'] = $props }
    if (-not $identChanged -and -not $props.Count) { return @{ changed = $false; detail = 'already as asked' } }
    [void](& $Arm 'PATCH' $path $body)
    # READ BACK
    $b = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
    $bi = @(Get-PimIdentityMoveMapPairs (Get-PimIdentityMoveField (Get-PimIdentityMoveField $b 'identity') 'userAssignedIdentities') | ForEach-Object { "$($_.key)".ToLowerInvariant() })
    $bad = New-Object System.Collections.Generic.List[string]
    if ("$ToId".Trim() -and -not ($bi -contains "$ToId".ToLowerInvariant())) { $bad.Add("$(@($ToId -split '/')[-1]) is not attached") }
    foreach ($r in $removed) { if ($bi -contains "$r".ToLowerInvariant()) { $bad.Add("$(@($r -split '/')[-1]) is still attached") } }
    $bpr = Get-PimIdentityMoveField $b 'properties'; $bcfg = Get-PimIdentityMoveField $bpr 'configuration'
    foreach ($r in @(Get-PimIdentityMoveField $bcfg 'registries')) { if ($r -and $fromSet.ContainsKey("$(Get-PimIdentityMoveField $r 'identity')".ToLowerInvariant())) { $bad.Add("registry $(Get-PimIdentityMoveField $r 'server') still pulls as the old identity") } }
    foreach ($s in @(Get-PimIdentityMoveField $bcfg 'secrets')) { if ($s -and "$(Get-PimIdentityMoveField $s 'keyVaultUrl')".Trim() -and $fromSet.ContainsKey("$(Get-PimIdentityMoveField $s 'identity')".ToLowerInvariant())) { $bad.Add("secret $(Get-PimIdentityMoveField $s 'name') still reads as the old identity") } }
    if (-not $ToSystem -and "$ToClientId".Trim()) {
        foreach ($c in @(Get-PimIdentityMoveField (Get-PimIdentityMoveField $bpr 'template') 'containers')) {
            if (-not $c -or "$(Get-PimIdentityMoveField $c 'name')" -eq 'signin-front') { continue }
            foreach ($nm in @($ClientIdEnvNames)) {
                $v = @(@(Get-PimIdentityMoveField $c 'env') | Where-Object { $_ -and "$(Get-PimIdentityMoveField $_ 'name')" -eq $nm } | ForEach-Object { "$(Get-PimIdentityMoveField $_ 'value')" })
                if (-not ($v -contains $ToClientId)) { $bad.Add("$(Get-PimIdentityMoveField $c 'name')/$nm is not $ToClientId on read-back") }
            }
        }
    }
    if ($bad.Count) { throw "read-back of $(@($ResourceId -split '/')[-1]): $($bad -join '; ')" }
    return @{ changed = $true; detail = ($changes -join '; ') }
}

# ---------------------------------------------------------------------------------------------------------- default seams
function Invoke-PimIdentityMoveDefaultDbInit {
    <#
      The SQL step through the in-network database job: ONE execution with PIM_DBINIT_PRINCIPALS = the one user, every other
      setting of the job as defined. The job exits 0 only when the user was READ BACK with the right SID and roles.
      Returns @{ ok; detail; execution }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][string]$UserName,
          [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @(), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$MaxPolls = 60)
    $api = Get-PimIdentityMoveApi
    $job = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$JobId`?api-version=$($api.aca)"
    if (-not $job) { return @{ ok = $false; detail = "the database job $(@($JobId -split '/')[-1]) is not there" } }
    $prin = ConvertTo-Json -Compress -InputObject @(@{ name = $UserName; appId = $AppId; roles = @($Roles) }) -Depth 5
    $cs = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-PimIdentityMoveField (Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'properties') 'template') 'containers')) {
        if (-not $c) { continue }
        $env = New-Object System.Collections.Generic.List[object]; $set = $false
        foreach ($e in @(Get-PimIdentityMoveField $c 'env')) { if (-not $e) { continue }; if ("$(Get-PimIdentityMoveField $e 'name')" -eq 'PIM_DBINIT_PRINCIPALS') { $env.Add(@{ name = 'PIM_DBINIT_PRINCIPALS'; value = $prin }); $set = $true } else { $env.Add($e) } }
        if (-not $set) { $env.Add(@{ name = 'PIM_DBINIT_PRINCIPALS'; value = $prin }) }
        $one = @{ name = "$(Get-PimIdentityMoveField $c 'name')"; image = "$(Get-PimIdentityMoveField $c 'image')"; env = @($env.ToArray()) }
        $res = Get-PimIdentityMoveField $c 'resources'; if ($null -ne $res) { $one.resources = $res }
        $cs.Add($one)
    }
    $st = & $Arm 'POST' "$JobId/start?api-version=$($api.aca)" @{ containers = @($cs.ToArray()) }
    $exe = "$(Get-PimIdentityMoveField $st 'name')"
    if (-not $exe) { return @{ ok = $false; detail = 'the database job did not start (no execution name returned)' } }
    $r = Wait-PimIdentityMoveJobExecution -Arm $Arm -JobId $JobId -Execution $exe -Sleep $Sleep -MaxPolls $MaxPolls
    return @{ ok = $r.ok; detail = "database job execution $exe : $($r.status)"; execution = $exe }
}

function Wait-PimIdentityMoveJobExecution {
    <# Poll one job execution until it ends. Returns @{ ok; status; execution }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][string]$Execution,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$MaxPolls = 60, [int]$PollSeconds = 15)
    $api = Get-PimIdentityMoveApi
    $status = 'unknown'; $ex = $null
    for ($i = 0; $i -lt $MaxPolls; $i++) {
        $ex = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$JobId/executions/$Execution`?api-version=$($api.aca)"
        $status = "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $ex 'properties') 'status')"
        if ($status -in @('Succeeded', 'Failed', 'Stopped', 'Degraded')) { break }
        & $Sleep $PollSeconds
    }
    return @{ ok = ($status -eq 'Succeeded'); status = $status; execution = $ex }
}

function Invoke-PimIdentityMoveDefaultProve {
    <#
      The PROOF for one app / job after its switch. App: the latest revision is the ready one, Healthy, and its template signs
      in as the new client id. Job: an execution that started after the switch Succeeded (started now for a role in
      -StartJobRoles; else the next scheduled run -- none yet = pending, a re-run continues). Returns @{ ok; pending; detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][object]$Row, [Parameter(Mandatory)][string]$ClientId,
          [string[]]$StartJobRoles = @('engine'), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$MaxPolls = 40)
    $api = Get-PimIdentityMoveApi
    $envOk = { param($tpl) $hit = $false; foreach ($c in @(Get-PimIdentityMoveField $tpl 'containers')) { if ($c -and "$(Get-PimIdentityMoveField $c 'name')" -ne 'signin-front') { foreach ($e in @(Get-PimIdentityMoveField $c 'env')) { if ($e -and "$(Get-PimIdentityMoveField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimIdentityMoveField $e 'value')" -ieq $ClientId) { $hit = $true } } } }; $hit }
    if ($Row.kind -eq 'app') {
        for ($i = 0; $i -lt $MaxPolls; $i++) {
            $a = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($Row.resourceId)`?api-version=$($api.aca)"
            $ap = Get-PimIdentityMoveField $a 'properties'
            $latest = "$(Get-PimIdentityMoveField $ap 'latestRevisionName')"; $ready = "$(Get-PimIdentityMoveField $ap 'latestReadyRevisionName')"
            if ($latest -and $latest -eq $ready) {
                $rev = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($Row.resourceId)/revisions/$latest`?api-version=$($api.aca)"
                $rp = Get-PimIdentityMoveField $rev 'properties'
                $h = "$(Get-PimIdentityMoveField $rp 'healthState')"; $rs = "$(Get-PimIdentityMoveField $rp 'runningState')"
                if ($h -eq 'Unhealthy' -or $rs -in @('Failed', 'Degraded')) { return @{ ok = $false; pending = $false; detail = "revision $latest $h / $rs" } }
                if ($h -eq 'Healthy' -and -not (& $envOk (Get-PimIdentityMoveField $rp 'template'))) { return @{ ok = $false; pending = $false; detail = "revision $latest is healthy but does not sign in as $ClientId" } }
                if ($h -eq 'Healthy') { return @{ ok = $true; pending = $false; detail = "revision $latest Healthy ($rs), signs in as $ClientId" } }
            }
            & $Sleep 15
        }
        return @{ ok = $false; pending = $false; detail = 'the new revision did not become healthy in time' }
    }
    $job = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($Row.resourceId)`?api-version=$($api.aca)"
    if (-not (& $envOk (Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'properties') 'template'))) { return @{ ok = $false; pending = $false; detail = "the job definition does not sign in as $ClientId" } }
    if ($StartJobRoles -contains $Row.role) {
        $st = & $Arm 'POST' "$($Row.resourceId)/start?api-version=$($api.aca)" @{}
        $exe = "$(Get-PimIdentityMoveField $st 'name')"
        if (-not $exe) { return @{ ok = $false; pending = $false; detail = 'the job did not start' } }
        $r = Wait-PimIdentityMoveJobExecution -Arm $Arm -JobId $Row.resourceId -Execution $exe -Sleep $Sleep -MaxPolls $MaxPolls
        return @{ ok = $r.ok; pending = $false; detail = "execution $exe $($r.status)" }
    }
    $since = $null
    try { $since = [datetime]::Parse("$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'systemData') 'lastModifiedAt')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $since = $null }
    $exes = @(Get-PimIdentityMoveList -Seam $Arm -Path "$($Row.resourceId)/executions?api-version=$($api.aca)")
    $after = @($exes | Where-Object {
        $t = $null; try { $t = [datetime]::Parse("$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { }
        $t -and $since -and $t -gt $since } | Sort-Object { "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime')" } -Descending)
    $done = @($after | Where-Object { "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'status')" -in @('Succeeded', 'Failed', 'Stopped', 'Degraded') })
    if (-not $done.Count) { return @{ ok = $false; pending = $true; detail = 'no run of the job since the switch yet -- re-run the mover after its next run' } }
    $s0 = "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $done[0] 'properties') 'status')"
    return @{ ok = ($s0 -eq 'Succeeded'); pending = $false; detail = "execution $(Get-PimIdentityMoveField $done[0] 'name') $s0 (after the switch)" }
}

# ---------------------------------------------------------------------------------------------------------- apply one role
function Invoke-PimIdentityMoveRole {
    <#
      APPLY one role of a plan (Get-PimIdentityMovePlan), steps 1-8, each read back. Seams: -Arm, -Graph, -DbInit
      { param($jobId, $userName, $appId, $roles) -> @{ ok; detail } } (default: the database job), -Prove { param($row,
      $clientId) -> @{ ok; pending; detail } } (default: Invoke-PimIdentityMoveDefaultProve), -Sleep { param($seconds) }.
      -DryRun: no write at all (every step says what it would do). -NoCleanup: stop after the proof.
      Returns the record: @{ role; target; state (done|proof-pending|customer-step|blocked|failed|dry-run|nothing-to-do);
      steps (in order: step, what, readBack, undo); copied; proof; removed; customerSteps; error; rollback }.
    #>
    param([Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][string]$Role,
          [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph,
          [scriptblock]$DbInit, [scriptblock]$Prove, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [string[]]$StartJobRoles = @('engine'), [switch]$DryRun, [switch]$NoCleanup)
    $api = Get-PimIdentityMoveApi
    $rp = @($Plan.roles | Where-Object { $_.role -eq $Role }) | Select-Object -First 1
    $rec = [ordered]@{ role = $Role; target = "id-pim-$Role"; state = ''; steps = New-Object System.Collections.Generic.List[object]; copied = New-Object System.Collections.Generic.List[string]
                       proof = New-Object System.Collections.Generic.List[string]; removed = New-Object System.Collections.Generic.List[string]; kept = New-Object System.Collections.Generic.List[string]
                       customerSteps = New-Object System.Collections.Generic.List[object]; error = ''; failedStep = ''; rollback = @(); startedUtc = [datetime]::UtcNow.ToString('o') }
    if (-not $rp) { $rec.state = 'nothing-to-do'; $rec.error = "no app / job of role '$Role' at this install"; return $rec }
    if ($rp.state -eq 'ok') { $rec.state = 'nothing-to-do'; $rec.proof.Add('every app / job of the role already signs in as its own identity; no old right left to remove'); return $rec }
    if ($rp.target -notmatch '^id-pim-[a-z]+$') { throw "refusing a target that is not id-pim-<role>: $($rp.target)" }
    $rg = "/subscriptions/$($Plan.subscriptionId)/resourceGroups/$($Plan.resourceGroup)"
    $step = { param($name, $what, $readBack, $undo) $rec.steps.Add([pscustomobject]@{ step = $name; what = $what; readBack = $readBack; undo = $undo; atUtc = [datetime]::UtcNow.ToString('o') }) }
    $fail = {
        param($name, $msg)
        $rec.state = 'failed'; $rec.failedStep = $name; $rec.error = "$msg"
        $rec.rollback = @(@($rec.steps.ToArray()) | Where-Object { "$($_.undo)".Trim() } | ForEach-Object { $_ })
        $rb = @($rec.rollback); $rev = New-Object System.Collections.Generic.List[object]; for ($i = $rb.Count - 1; $i -ge 0; $i--) { $rev.Add($rb[$i]) }; $rec.rollback = @($rev.ToArray())
    }
    $dbJobFn = if ($DbInit) { $DbInit } else { { param($jobId, $userName, $appId, $roles) Invoke-PimIdentityMoveDefaultDbInit -Arm $Arm -JobId $jobId -UserName $userName -AppId $appId -Roles $roles -Sleep $Sleep } }
    $proveFn = if ($Prove) { $Prove } else { { param($row, $clientId) Invoke-PimIdentityMoveDefaultProve -Arm $Arm -Row $row -ClientId $clientId -StartJobRoles $StartJobRoles -Sleep $Sleep } }
    $tgtName = $rp.target; $tgtId = "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$tgtName"
    $tgtPid = "$($rp.targetPrincipalId)"; $tgtCid = "$($rp.targetClientId)"
    $cur = ''
    try {
        # ------------------------------------------------------------------ 1 identity
        $cur = 'identity'
        if ($rp.state -eq 'move') {
            $idObj = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$tgtId`?api-version=$($api.msi)"
            if (-not $idObj) {
                $loc = if ($Plan.location) { $Plan.location } else { "$(@($rp.resources)[0].location)" }
                if ($DryRun) { & $step 'identity' "would create $tgtName in $($Plan.resourceGroup) ($loc), tag pim-component=$Role" '' ''; $rec.state = 'dry-run' }
                else {
                    [void](& $Arm 'PUT' "$tgtId`?api-version=$($api.msi)" @{ location = $loc; tags = @{ 'pim-component' = $Role } })
                    $idObj = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$tgtId`?api-version=$($api.msi)"
                    if (-not $idObj -or -not "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $idObj 'properties') 'principalId')") { throw "$tgtName was created but does not read back with a principal id" }
                    & $step 'identity' "created $tgtName (tag pim-component=$Role)" 'read back: principal + client id' "Invoke-PimArm -Method DELETE -Path '$tgtId`?api-version=$($api.msi)'"
                }
            } else { & $step 'identity' "$tgtName exists" 'read back' '' }
            if ($idObj) { $ip = Get-PimIdentityMoveField $idObj 'properties'; $tgtPid = "$(Get-PimIdentityMoveField $ip 'principalId')"; $tgtCid = "$(Get-PimIdentityMoveField $ip 'clientId')" }
        }
        if ($DryRun -and -not $tgtPid) { $tgtPid = "<object id of $tgtName>"; $tgtCid = "<client id of $tgtName>" }
        # root rights the Support app cannot write: a customer step, now with the real object id
        foreach ($a in @($rp.toCopy.azureRootCustomer)) {
            $rec.customerSteps.Add([pscustomobject]@{ when = 'before the switch'; what = "grant $tgtName the role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at the tenant root (the Support app has no User Access Administrator there)"; command = (Get-PimIdentityMoveCustomerCommand -Action add -PrincipalId $tgtPid -PrincipalName $tgtName -RoleDefinitionId $a.roleDefinitionId -Scope $a.scope) })
        }
        if ($true) {   # steps 2-4 run in every state: a role already signing in as its target still gets what an old identity it drops holds
            # ------------------------------------------------------------------ 2 graph
            $cur = 'graph'
            foreach ($g in @($rp.toCopy.graph)) {
                $what = "app role $($g.appRoleId) of $(if ($g.resourceDisplayName) { $g.resourceDisplayName } else { $g.resourceId })"
                if ($DryRun) { & $step 'graph' "would grant $tgtName $what" '' ''; continue }
                $r = & $Graph 'POST' "/servicePrincipals/$tgtPid/appRoleAssignments" @{ principalId = $tgtPid; resourceId = $g.resourceId; appRoleId = $g.appRoleId }
                $back = @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$tgtPid/appRoleAssignments" | Where-Object { "$(Get-PimIdentityMoveField $_ 'resourceId')" -ieq $g.resourceId -and "$(Get-PimIdentityMoveField $_ 'appRoleId')" -ieq $g.appRoleId })
                if (-not $back.Count) { throw "$what was granted to $tgtName but does not read back" }
                $aid = "$(Get-PimIdentityMoveField $back[0] 'id')"
                & $step 'graph' "granted $tgtName $what" 'read back' "Invoke-PimGraph -Method DELETE -Path '/servicePrincipals/$tgtPid/appRoleAssignments/$aid'"
                $rec.copied.Add("graph: $what")
            }
            foreach ($g in @($rp.toCopy.groups)) {
                if ($DryRun) { & $step 'graph' "would add $tgtName to the PIM group $($g.displayName)" '' ''; continue }
                [void](& $Graph 'POST' "/groups/$($g.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$tgtPid" })
                $back = @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$tgtPid/memberOf/microsoft.graph.group?`$select=id,displayName" | Where-Object { "$(Get-PimIdentityMoveField $_ 'id')" -ieq $g.id })
                if (-not $back.Count) { throw "$tgtName was added to $($g.displayName) but the membership does not read back" }
                & $step 'graph' "added $tgtName to the PIM group $($g.displayName)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/groups/$($g.id)/members/$tgtPid/`$ref'"
                $rec.copied.Add("group: $($g.displayName)")
            }
            foreach ($d in @($rp.toCopy.dirRoles)) {
                if ($DryRun) { & $step 'graph' "would assign $tgtName the directory role $($d.roleDefinitionId) at $($d.directoryScopeId)" '' ''; continue }
                $r = & $Graph 'POST' '/roleManagement/directory/roleAssignments' @{ principalId = $tgtPid; roleDefinitionId = $d.roleDefinitionId; directoryScopeId = $(if ($d.directoryScopeId) { $d.directoryScopeId } else { '/' }) }
                $back = @(Get-PimIdentityMoveList -Seam $Graph -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$tgtPid'" | Where-Object { "$(Get-PimIdentityMoveField $_ 'roleDefinitionId')" -ieq $d.roleDefinitionId })
                if (-not $back.Count) { throw "the directory role $($d.roleDefinitionId) does not read back on $tgtName" }
                & $step 'graph' "assigned $tgtName the directory role $($d.roleDefinitionId)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/roleManagement/directory/roleAssignments/$(Get-PimIdentityMoveField $back[0] 'id')'"
                $rec.copied.Add("directory role: $($d.roleDefinitionId)")
            }
            # ------------------------------------------------------------------ 3 azure
            $cur = 'azure'
            foreach ($a in @($rp.toCopy.azure)) {
                $sc = "$($a.scope)".TrimEnd('/')
                $name = New-PimIdentityMoveGuid -Seed "$tgtPid|$($a.roleDefinitionId)|$sc"
                $aPath = "$sc/providers/Microsoft.Authorization/roleAssignments/$name`?api-version=$($api.auth)"
                $what = "Azure role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $(if ($sc) { $sc } else { '/' })"
                if ($DryRun) { & $step 'azure' "would grant $tgtName the $what" '' ''; continue }
                [void](& $Arm 'PUT' $aPath @{ properties = @{ roleDefinitionId = $a.roleDefinitionId; principalId = $tgtPid; principalType = 'ServicePrincipal' } })
                $back = Invoke-PimIdentityMoveGet -Seam $Arm -Path $aPath
                if (-not $back -or "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $back 'properties') 'principalId')" -ine $tgtPid) { throw "the $what does not read back on $tgtName" }
                & $step 'azure' "granted $tgtName the $what" 'read back' "Invoke-PimArm -Method DELETE -Path '$aPath'"
                $rec.copied.Add("azure: $what")
            }
            # a root right the customer grants: read back before anything switches (no gap)
            if (@($rp.toCopy.azureRootCustomer).Count -and -not $DryRun) {
                $now = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $Plan.subscriptionId -PrincipalId $tgtPid -TenantId $Plan.tenantId -ExtraScopes $Plan.extraScopes -PimGroupNames $Plan.pimGroupNames
                $missing = @(Get-PimIdentityRightsToCopy -SourceAzure @($rp.toCopy.azureRootCustomer) -TargetAzure @($now.azure)).azure
                if (@($missing).Count) {
                    $rec.state = 'customer-step'; $rec.error = "the customer grants $(@($missing).Count) right(s) at the tenant root first (the Support app has no root access); then run again -- nothing switched, nothing removed"
                    return $rec
                }
                foreach ($a in @($rp.toCopy.azureRootCustomer)) { $rec.copied.Add("azure (customer): $(@("$($a.roleDefinitionId)" -split '/')[-1]) at the tenant root, read back") }
            }
            # ------------------------------------------------------------------ 4 kv (access policies; RBAC + AcrPull were step 3)
            $cur = 'kv'
            foreach ($k in @($rp.toCopy.kv)) {
                $what = "Key Vault access policy on $($k.vaultName)"
                if ($DryRun) { & $step 'kv' "would add $tgtName to the $what" '' ''; continue }
                $tid = if ($k.tenantId) { $k.tenantId } else { $Plan.tenantId }
                [void](& $Arm 'PUT' "$($k.vaultId)/accessPolicies/add?api-version=$($api.kv)" @{ properties = @{ accessPolicies = @(@{ tenantId = $tid; objectId = $tgtPid; permissions = $k.permissions }) } })
                $v = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($k.vaultId)?api-version=$($api.kv)"
                $have = @(@(Get-PimIdentityMoveField (Get-PimIdentityMoveField $v 'properties') 'accessPolicies') | Where-Object { $_ -and "$(Get-PimIdentityMoveField $_ 'objectId')" -ieq $tgtPid } | ForEach-Object { [pscustomobject]@{ vaultId = $k.vaultId; permissions = (Get-PimIdentityMoveField $_ 'permissions') } })
                if (@(Get-PimIdentityMoveKvMissing -Source @($k) -Target $have).Count) { throw "the $what does not read back on $tgtName" }
                & $step 'kv' "added $tgtName to the $what" 'read back' "Invoke-PimArm -Method PUT -Path '$($k.vaultId)/accessPolicies/remove?api-version=$($api.kv)' -Body @{ properties = @{ accessPolicies = @(@{ tenantId = '$tid'; objectId = '$tgtPid'; permissions = @{} }) } }"
                $rec.copied.Add("kv: $($k.vaultName)")
            }
            # ------------------------------------------------------------------ 5 sql
            $cur = 'sql'
            if ($rp.sql.needed -and $rp.state -eq 'move') {
                if (-not "$($rp.sql.jobId)".Trim()) {
                    $rec.state = 'blocked'; $rec.failedStep = 'sql'
                    $rec.error = "the in-network database job (ca-pim-dbinit / caj-pim-dbinit) is not on this install -- the contained user $tgtName ($(@($rp.sql.roles) -join ', ')) cannot be made; the update that creates the job (OPEN-06) comes first. Nothing switched, nothing removed."
                    $rec.rollback = @(@($rec.steps.ToArray()) | Where-Object { "$($_.undo)".Trim() }); $rb = @($rec.rollback); $rev = New-Object System.Collections.Generic.List[object]; for ($i = $rb.Count - 1; $i -ge 0; $i--) { $rev.Add($rb[$i]) }; $rec.rollback = @($rev.ToArray())
                    return $rec
                }
                if ($DryRun) { & $step 'sql' "would run $($rp.sql.job) once to create the database user $tgtName ($(@($rp.sql.roles) -join ', '))" '' '' }
                else {
                    $r = & $dbJobFn $rp.sql.jobId $tgtName $tgtCid @($rp.sql.roles)
                    if (-not $r -or -not $r.ok) { throw "the database job did not make the user $tgtName : $(if ($r) { $r.detail })" }
                    & $step 'sql' "database user $tgtName ($(@($rp.sql.roles) -join ', ')) through $($rp.sql.job)" "read back by the job: $($r.detail)" "the user stays harmless until the switch; remove it with the database job if wanted"
                    $rec.copied.Add("sql: $tgtName ($(@($rp.sql.roles) -join ', '))")
                }
            }
        }
        # ------------------------------------------------------------------ 6 switch + 7 prove, per app / job
        # the database job signs in to SQL with PIM_DBINIT_MI_CLIENT_ID (none = its system identity), so it is switched too
        $envNames = if ($Role -eq 'dbinit') { @('PIM_ManagedIdentityClientId', 'PIM_DBINIT_MI_CLIENT_ID') } else { @('PIM_ManagedIdentityClientId') }
        $envNamesTxt = "@('" + ($envNames -join "', '") + "')"
        foreach ($row in @($rp.resources)) {
            $cur = 'switch'
            $fromIds = @($row.sources | ForEach-Object { "$($_.id)" })
            $fromCids = @($row.sources | Where-Object { "$($_.clientId)".Trim() } | ForEach-Object { "$($_.clientId)" })
            if (-not $row.signsInAsTarget -or @($row.settings).Count) {
                $sw = Set-PimIdentityMoveSwitch -Arm $Arm -ResourceId $row.resourceId -FromIds $fromIds -FromClientIds $fromCids -ToId $tgtId -ToClientId $tgtCid -ClientIdEnvNames $envNames -DryRun:$DryRun
                $prevSys = -not @($row.sources | Where-Object { $_.kind -eq 'user' }).Count
                $undoSw = if ($prevSys) { "Set-PimIdentityMoveSwitch -Arm `$arm -ResourceId '$($row.resourceId)' -FromIds @('$tgtId') -ToSystem -ClientIdEnvNames $envNamesTxt" }
                          else { $u0 = @($row.sources | Where-Object { $_.kind -eq 'user' })[0]; "Set-PimIdentityMoveSwitch -Arm `$arm -ResourceId '$($row.resourceId)' -FromIds @('$tgtId') -FromClientIds @('$tgtCid') -ToId '$($u0.id)' -ToClientId '$($u0.clientId)' -ClientIdEnvNames $envNamesTxt" }
                & $step 'switch' "$(if ($DryRun) { 'would switch' } else { 'switched' }) $($row.resource): $($sw.detail)" $(if ($DryRun) { '' } else { 'read back' }) $(if ($DryRun -or -not $sw.changed) { '' } else { $undoSw })
            }
            if ($DryRun) { & $step 'prove' "would prove $($row.resource) runs as $tgtName" '' ''; continue }
            $cur = 'prove'
            $pv = & $proveFn $row $tgtCid
            if ($pv -and $pv.pending) { $rec.proof.Add("$($row.resource): PENDING -- $($pv.detail)"); $rec.state = 'proof-pending'; continue }
            if (-not $pv -or -not $pv.ok) { throw "the proof failed for $($row.resource): $(if ($pv) { $pv.detail })" }
            $rec.proof.Add("$($row.resource): $($pv.detail)")
            & $step 'prove' "$($row.resource) proven: $($pv.detail)" 'proof' ''
        }
        if ($DryRun) {
            foreach ($row in @($rp.resources)) { foreach ($s in @($row.sources)) { & $step 'cleanup' "would then remove the copied rights of $($s.name) (after the proof)" '' '' } }
            $rec.state = 'dry-run'; return $rec
        }
        if ($rec.state -eq 'proof-pending') { return $rec }
        if ($NoCleanup) { $rec.state = 'proven'; return $rec }
        # ------------------------------------------------------------------ 8 cleanup (only after EVERY app / job of the role is proven)
        $cur = 'cleanup'
        Invoke-PimIdentityMoveCleanup -Plan $Plan -RolePlan $rp -Arm $Arm -Graph $Graph -TargetId $tgtId -TargetPrincipalId $tgtPid -TargetClientId $tgtCid -Record $rec -Step $step
        $rec.state = 'done'
    } catch {
        & $fail $cur "$($_.Exception.Message)"
    }
    return $rec
}

function Invoke-PimIdentityMoveCleanup {
    <#
      Step 8, called only after the proof. Removes ONLY rights the target now holds too (read again): a system-assigned source
      loses them (the identity stays enabled); a user-assigned source is detached from each app / job of the role, and loses
      its rights only when no PIM app / job and no SQL server / storage account of the group still uses it. Root rights
      without root access, and the old database user, are listed (customer step / kept).
    #>
    param([Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][object]$RolePlan, [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph,
          [Parameter(Mandatory)][string]$TargetId, [Parameter(Mandatory)][string]$TargetPrincipalId, [Parameter(Mandatory)][string]$TargetClientId, [Parameter(Mandatory)][System.Collections.IDictionary]$Record, [Parameter(Mandatory)][scriptblock]$Step)
    $api = Get-PimIdentityMoveApi
    $rec = $Record
    $now = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $Plan.subscriptionId -PrincipalId $TargetPrincipalId -TenantId $Plan.tenantId -Vaults @(Read-PimIdentityMoveInstall -Arm $Arm -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup).vaults -ExtraScopes $Plan.extraScopes -PimGroupNames $Plan.pimGroupNames
    # detach shared user-assigned sources from each app / job of the role
    foreach ($row in @($RolePlan.resources)) {
        $users = @($row.sources | Where-Object { $_.kind -eq 'user' })
        if (-not $users.Count) { continue }
        $sw = Set-PimIdentityMoveSwitch -Arm $Arm -ResourceId $row.resourceId -FromIds @($users | ForEach-Object { $_.id }) -FromClientIds @($users | Where-Object { $_.clientId } | ForEach-Object { $_.clientId }) -ToId $TargetId -ToClientId $TargetClientId -ClientIdEnvNames $(if ($RolePlan.role -eq 'dbinit') { @('PIM_ManagedIdentityClientId', 'PIM_DBINIT_MI_CLIENT_ID') } else { @('PIM_ManagedIdentityClientId') }) -Detach @($users | ForEach-Object { $_.id })
        if ($sw.changed) { & $Step 'cleanup' "$($row.resource): $($sw.detail)" 'read back' "Set-PimIdentityMoveSwitch -Arm `$arm -ResourceId '$($row.resourceId)' -ToId '$(@($users)[0].id)'"; $rec.removed.Add("$($row.resource): detached $(@($users | ForEach-Object { $_.name }) -join ', ')") }
    }
    # who still uses each user-assigned source (a fresh read of the group)
    $inst = Read-PimIdentityMoveInstall -Arm $Arm -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup
    $users = @{}
    foreach ($o in @(@($inst.apps) + @($inst.jobs) + @($inst.sqlServers) + @($inst.storage) | Where-Object { $_ })) {
        foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimIdentityMoveField (Get-PimIdentityMoveField $o 'identity') 'userAssignedIdentities'))) {
            $k = "$($pair.key)".ToLowerInvariant(); if (-not $users.ContainsKey($k)) { $users[$k] = @() }; $users[$k] += "$(Get-PimIdentityMoveField $o 'name')"
        }
    }
    foreach ($s in @($RolePlan.sources)) {
        if ($s.kind -eq 'user') {
            $still = @($users["$($s.id)".ToLowerInvariant()] | Where-Object { $_ })
            if ($still.Count) { $rec.kept.Add("$($s.name): rights kept -- still used by $($still -join ', ')"); continue }
        }
        $sr = $RolePlan.perSource["$($s.principalId)".ToLowerInvariant()]
        if (-not $sr) { continue }
        $haveA = @{}; foreach ($a in @($now.azure)) { $haveA[(("$($a.roleDefinitionId)" -replace '^.*/roleDefinitions/', '').ToLowerInvariant() + '|' + "$($a.scope)".TrimEnd('/').ToLowerInvariant())] = $true }
        foreach ($a in @($sr.azure)) {
            $k = ("$($a.roleDefinitionId)" -replace '^.*/roleDefinitions/', '').ToLowerInvariant() + '|' + "$($a.scope)".TrimEnd('/').ToLowerInvariant()
            if (-not $haveA.ContainsKey($k)) { $rec.kept.Add("$($s.name): Azure role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope) kept -- $($RolePlan.target) does not hold it"); continue }
            if ($a.root -and -not $Plan.supportHasRootAccess) { $rec.customerSteps.Add([pscustomobject]@{ when = 'after the proof'; what = "remove the old identity's role at the tenant root"; command = (Get-PimIdentityMoveCustomerCommand -Action remove -PrincipalId $s.principalId -RoleDefinitionId $a.roleDefinitionId -Scope $a.scope) }); continue }
            [void](& $Arm 'DELETE' "$($a.id)?api-version=$($api.auth)" $null)
            if (Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($a.id)?api-version=$($api.auth)") { throw "$($s.name): the Azure role $($a.id) is still there after the delete" }
            & $Step 'cleanup' "removed from $($s.name): Azure role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope)" 'read back: gone' "Invoke-PimArm -Method PUT -Path '$($a.id)?api-version=$($api.auth)' -Body @{ properties = @{ roleDefinitionId = '$($a.roleDefinitionId)'; principalId = '$($s.principalId)'; principalType = 'ServicePrincipal' } }"
            $rec.removed.Add("$($s.name): azure $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope)")
        }
        $haveG = @{}; foreach ($g in @($now.graph)) { $haveG["$($g.resourceId)|$($g.appRoleId)".ToLowerInvariant()] = $true }
        foreach ($g in @($sr.graph)) {
            if (-not $haveG.ContainsKey("$($g.resourceId)|$($g.appRoleId)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): app role $($g.appRoleId) kept -- the target does not hold it"); continue }
            [void](& $Graph 'DELETE' "/servicePrincipals/$($s.principalId)/appRoleAssignments/$($g.id)" $null)
            & $Step 'cleanup' "removed from $($s.name): app role $($g.appRoleId)" 'removed' "Invoke-PimGraph -Method POST -Path '/servicePrincipals/$($s.principalId)/appRoleAssignments' -Body @{ principalId = '$($s.principalId)'; resourceId = '$($g.resourceId)'; appRoleId = '$($g.appRoleId)' }"
            $rec.removed.Add("$($s.name): graph $($g.appRoleId)")
        }
        $haveM = @{}; foreach ($g in @($now.groups)) { $haveM["$($g.id)".ToLowerInvariant()] = $true }
        foreach ($g in @($sr.groups)) {
            if (-not $haveM.ContainsKey("$($g.id)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): $($g.displayName) membership kept -- the target is not a member"); continue }
            [void](& $Graph 'DELETE' "/groups/$($g.id)/members/$($s.principalId)/`$ref" $null)
            & $Step 'cleanup' "removed $($s.name) from the PIM group $($g.displayName)" 'removed' "Invoke-PimGraph -Method POST -Path '/groups/$($g.id)/members/`$ref' -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/$($s.principalId)' }"
            $rec.removed.Add("$($s.name): group $($g.displayName)")
        }
        $haveD = @{}; foreach ($d in @($now.dirRoles)) { $haveD["$($d.roleDefinitionId)".ToLowerInvariant()] = $true }
        foreach ($d in @($sr.dirRoles)) {
            if (-not $haveD.ContainsKey("$($d.roleDefinitionId)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): directory role $($d.roleDefinitionId) kept"); continue }
            [void](& $Graph 'DELETE' "/roleManagement/directory/roleAssignments/$($d.id)" $null)
            & $Step 'cleanup' "removed from $($s.name): directory role $($d.roleDefinitionId)" 'removed' "Invoke-PimGraph -Method POST -Path '/roleManagement/directory/roleAssignments' -Body @{ principalId = '$($s.principalId)'; roleDefinitionId = '$($d.roleDefinitionId)'; directoryScopeId = '$($d.directoryScopeId)' }"
            $rec.removed.Add("$($s.name): directory role $($d.roleDefinitionId)")
        }
        foreach ($k in @($sr.kv)) {
            $tk = @(@($now.kv) | Where-Object { "$($_.vaultId)" -ieq "$($k.vaultId)" })
            if (@(Get-PimIdentityMoveKvMissing -Source @($k) -Target $tk).Count) { $rec.kept.Add("$($s.name): access policy on $($k.vaultName) kept -- the target does not hold it all"); continue }
            [void](& $Arm 'PUT' "$($k.vaultId)/accessPolicies/remove?api-version=$($api.kv)" @{ properties = @{ accessPolicies = @(@{ tenantId = $(if ($k.tenantId) { $k.tenantId } else { $Plan.tenantId }); objectId = $s.principalId; permissions = $k.permissions }) } })
            & $Step 'cleanup' "removed $($s.name) from the access policy on $($k.vaultName)" 'removed' "Invoke-PimArm -Method PUT -Path '$($k.vaultId)/accessPolicies/add?api-version=$($api.kv)' -Body <the policy in this record>"
            $rec.removed.Add("$($s.name): kv $($k.vaultName)")
        }
        if ($RolePlan.sql.needed) { $rec.kept.Add("$($s.name): its database user is kept (removing it is a database-job step, not done by the mover)") }
    }
}

function Format-PimIdentityMoveTable {
    <# PURE. role -> old -> new -> copied (read back) -> proof -> old rights removed, one row per role record. #>
    param([AllowEmptyCollection()][object[]]$Records = @(), [AllowNull()][object]$Plan = $null)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Records | Where-Object { $_ })) {
        $rp = if ($Plan) { @($Plan.roles | Where-Object { $_.role -eq $r.role }) | Select-Object -First 1 } else { $null }
        $out.Add([pscustomobject]@{
            role = $r.role; old = $(if ($rp) { (@($rp.sources | ForEach-Object { $_.name }) -join ', ') } else { '' }); new = $r.target; state = $r.state
            copied = (@($r.copied) -join '; '); proof = (@($r.proof) -join '; '); removed = (@($r.removed) -join '; '); customer = (@($r.customerSteps | ForEach-Object { $_.command }) -join ' | ')
        })
    }
    return @($out.ToArray())
}
