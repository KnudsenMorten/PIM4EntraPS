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
# the shared, override-free job start (ACA-START-OVERRIDE): every job start the mover makes goes through it
if (-not (Get-Command Start-PimAcaJobExecution -ErrorAction SilentlyContinue)) {
    $__pimAca = Join-Path $PSScriptRoot 'PIM-ArmContainerApps.ps1'
    if (Test-Path -LiteralPath $__pimAca) { . $__pimAca }
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

function ConvertTo-PimIdentityMoveUtc {
    <#
      PURE. An ARM time as UTC, or $null. PowerShell 7's ConvertFrom-Json turns '...Z' into a [datetime] of kind Utc and
      '...+00:00' into one of kind LOCAL -- re-parsing its TEXT drops the kind (internal 2026-11-08: a 08:15Z run read as
      09:15Z and was taken as the proof of an 08:16Z switch). A [datetime] is converted by its kind (Unspecified = UTC); a
      string is parsed with its offset, a string without one taken as UTC.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    try { return [DateTimeOffset]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime } catch { return $null }
}

function Invoke-PimIdentityMoveGraphAdd {
    <# A Graph POST that ADDS a right; "already exists" (a re-run, or a read that lagged behind an earlier add) counts as done. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Body)
    try { return (& $Graph 'POST' $Path $Body) } catch {
        if ("$($_.Exception.Message)" -match '(?i)\b409\b|already exist|One or more added object references already exist|Permission being assigned already exists|RoleAssignmentExists|conflicting object') { return $null }
        throw
    }
}

function Wait-PimIdentityMoveGraphBack {
    <# Directory replication: a grant Graph accepted may not show in a read straight after it (internal id-pim-engine
       2026-11-08 07:33Z). Runs -Read up to -Tries times, -WaitSeconds apart, until it returns something. #>
    param([Parameter(Mandatory)][scriptblock]$Read, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 8, [int]$WaitSeconds = 5)
    for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
        if ($i -gt 1) { & $Sleep $WaitSeconds }
        $b = @(& $Read)
        if ($b.Count) { return ,$b }
    }
    return ,@()
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
    # an absent resource group is a wrong subscription / name, NEVER "nothing to move" (internal 2026-11-08: the plan of a
    # resource group in another subscription listed no roles and said nothing)
    if (-not $rgObj) { throw "resource group $ResourceGroup was not found in subscription $SubscriptionId (wrong subscription or name?) -- nothing planned" }
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
    # APP-REG-OWNER (framework SECAUDIT-1a item 2): ownership of PIM's OWN product registrations is a right too (the updater
    # owns them). Only registrations whose display name is a PIM product name; a read failure leaves the list empty.
    $out.owned = @()
    try {
        $out.owned = @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$p/ownedObjects/microsoft.graph.application?`$select=id,appId,displayName" |
            Where-Object { Test-PimIdentityMovePimApp -DisplayName "$(Get-PimIdentityMoveField $_ 'displayName')" } |
            ForEach-Object { [pscustomobject]@{ id = "$(Get-PimIdentityMoveField $_ 'id')"; appId = "$(Get-PimIdentityMoveField $_ 'appId')"; displayName = "$(Get-PimIdentityMoveField $_ 'displayName')" } })
    } catch { $out.owned = @() }
    return $out
}

function Read-PimIdentityMoveFics {
    <#
      READ. The federated identity credentials on PIM's own product registrations whose SUBJECT is one of -PrincipalIds (the
      sign-in front signs in as the web identity through one: Set-PimManagerSigninFront.ps1 Get-PimSigninFrontFicSpec).
      Returns @(@{ appObjectId; appName; id; name; issuer; subject; audiences }). A read failure returns what was read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyCollection()][string[]]$PrincipalIds = @())
    $want = @($PrincipalIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $want.Count) { return @() }
    $apps = @()
    try { $apps = @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications?`$filter=startswith(displayName,'PIM')&`$select=id,displayName" | Where-Object { Test-PimIdentityMovePimApp -DisplayName "$(Get-PimIdentityMoveField $_ 'displayName')" }) } catch { $apps = @() }
    foreach ($a in $apps) {
        $aid = "$(Get-PimIdentityMoveField $a 'id')"
        $f = @(); try { $f = @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications/$aid/federatedIdentityCredentials") } catch { $f = @() }
        foreach ($c in $f) {
            if ($want -contains "$(Get-PimIdentityMoveField $c 'subject')".Trim().ToLowerInvariant()) {
                $out.Add([pscustomobject]@{ appObjectId = $aid; appName = "$(Get-PimIdentityMoveField $a 'displayName')"; id = "$(Get-PimIdentityMoveField $c 'id')"; name = "$(Get-PimIdentityMoveField $c 'name')"
                                            issuer = "$(Get-PimIdentityMoveField $c 'issuer')"; subject = "$(Get-PimIdentityMoveField $c 'subject')"; audiences = @(Get-PimIdentityMoveField $c 'audiences') })
            }
        }
    }
    return @($out.ToArray())
}

function Test-PimIdentityMovePimApp {
    <# PURE. A PIM product registration by its display name (the product names, optionally with an install label in brackets). #>
    param([AllowEmptyString()][string]$DisplayName)
    return ("$DisplayName".Trim() -match '^(?i)(PIM Manager|PIM Manager Engine|PIM Activator|PIM Manager Deploy|PIM access request API|PIM4EntraPS Manager|PIM4EntraPS Engine)( \(.+\))?$')
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
function Get-PimIdentityMoveRoleNeeds {
    <#
      PURE. -NeedOnly (Invardia ruling 2026-11-08, framework 12.11c x 4.3): what a role may take over from a SHARED
      (user-assigned, several roles) identity. From the 4.3 rights map (2026-11-08, code-read): Azure role definition guids,
      PIM group names and directory role ids per role. Graph app roles and Key Vault access policies are never taken from a
      shared identity (each role's own system identity carries its real Graph set; access policies are legacy). A role not
      listed takes AcrPull only.
    #>
    param([Parameter(Mandatory)][string]$Role)
    $acr = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
    $n = switch ("$Role".ToLowerInvariant()) {
        'web'      { @{ azure = @('acdd72a7-3385-48ef-bd42-f606fba81ae7', 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b', 'e147488a-f6f5-4113-8e2d-b22465e65bf6', $acr); groups = @(); dirRoles = @() } }
        'engine'   { @{ azure = @('acdd72a7-3385-48ef-bd42-f606fba81ae7', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3', $acr); groups = @('grp-pim-powerbi-admin-api'); dirRoles = @('a9ea8996-122f-4c74-9520-8edcd192826c') } }
        'updater'  { @{ azure = @('b24988ac-6180-42a0-ab88-20f7382dd24c', $acr); groups = @(); dirRoles = @() } }
        'dbinit'   { @{ azure = @($acr); groups = @('grp-pim-sql-admins'); dirRoles = @() } }
        'requests' { @{ azure = @('0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3', $acr); groups = @(); dirRoles = @() } }
        'asbuilt'  { @{ azure = @('ba92f5b4-2d11-453d-a403-e96b0029c9fe', $acr); groups = @(); dirRoles = @() } }
        default    { @{ azure = @($acr); groups = @(); dirRoles = @() } }
    }
    return $n
}

function Select-PimIdentityMoveNeeded {
    <# PURE. Splits ONE shared source's rights into what -Role needs (kept) and what it does not (notCopied, named). #>
    param([Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][hashtable]$Rights, [string]$SourceName = 'the shared identity')
    $need = Get-PimIdentityMoveRoleNeeds -Role $Role
    $keep = @{ azure = @(); graph = @(); groups = @(); dirRoles = @(); kv = @() }; $not = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Rights.azure)) { if (-not $a) { continue }; $g = @("$($a.roleDefinitionId)" -split '/')[-1].ToLowerInvariant(); if ($need.azure -contains $g) { $keep.azure += $a } else { $not.Add("Azure role $g at $($a.scope) (from $SourceName)") } }
    foreach ($m in @($Rights.groups)) { if (-not $m) { continue }; if (@($need.groups | Where-Object { $_ -ieq "$($m.displayName)" }).Count) { $keep.groups += $m } else { $not.Add("PIM group $($m.displayName) (from $SourceName)") } }
    foreach ($d in @($Rights.dirRoles)) { if (-not $d) { continue }; if ($need.dirRoles -contains "$($d.roleDefinitionId)".ToLowerInvariant()) { $keep.dirRoles += $d } else { $not.Add("directory role $($d.roleDefinitionId) (from $SourceName)") } }
    foreach ($g in @($Rights.graph)) { if ($g) { $not.Add("Graph app role $($g.appRoleId) (from $SourceName)") } }
    foreach ($k in @($Rights.kv)) { if ($k) { $not.Add("Key Vault access policy on $($k.vaultName) (from $SourceName)") } }
    return @{ keep = $keep; notCopied = @($not.ToArray()) }
}

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
          [hashtable]$SqlRoles = @{}, [AllowNull()][object]$Install = $null, [switch]$NeedOnly)
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
        $sr = @{ azure = @(); graph = @(); groups = @(); dirRoles = @(); kv = @(); owned = @() }
        $perSource = @{}; $notCopied = New-Object System.Collections.Generic.List[string]
        foreach ($s in $sources) {
            $r = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -PrincipalId $s.principalId -TenantId $TenantId -Vaults $inst.vaults -ExtraScopes $ExtraScopes -PimGroupNames $PimGroupNames
            $perSource["$($s.principalId)".ToLowerInvariant()] = $r
            # -NeedOnly: a SHARED (user-assigned) source gives only what this role needs; the role's own system identity gives all
            $use = $r
            if ($NeedOnly -and "$($s.kind)" -eq 'user') { $sel = Select-PimIdentityMoveNeeded -Role $role -Rights $r -SourceName "$($s.name)"; $use = $sel.keep; foreach ($x in @($sel.notCopied)) { $notCopied.Add($x) } }
            # SEC-09 (framework 4.5): the SQL admin group's ONLY standing member is the database job -- never copied to another
            # role, not even from the role's own system identity (Invardia 2026-11-08: the updater leaves it in its move).
            # ALWAYS, with or without -NeedOnly: without it the customer moves copied the old updater's membership to
            # id-pim-updater ("updater-not-sql-admin" missing after the move, a customer test install 2026-11-08 23:03Z).
            if ($role -ne 'dbinit' -and @($use.groups | Where-Object { "$($_.displayName)" -ieq 'grp-pim-sql-admins' }).Count) {
                $use = @{ azure = @($use.azure); graph = @($use.graph); groups = @($use.groups | Where-Object { "$($_.displayName)" -ine 'grp-pim-sql-admins' }); dirRoles = @($use.dirRoles); kv = @($use.kv) }
                $notCopied.Add("PIM group grp-pim-sql-admins (from $($s.name); SEC-09: only the database job is a standing member)")
            }
            foreach ($k in @('azure', 'graph', 'groups', 'dirRoles', 'kv')) { $sr[$k] = @(@($sr[$k]) + @($use[$k])) }
            # app registration ownership moves with the UPDATER role only (it is the updater's right; framework SECAUDIT-1a)
            if ($role -eq 'updater') { $sr.owned = @(@($sr.owned) + @($r.owned)) }
            elseif (@($r.owned).Count) { foreach ($ow in @($r.owned)) { $notCopied.Add("owner of the app registration $($ow.displayName) (from $($s.name); only the updater owns them)") } }
        }
        $tr = Read-PimIdentityMoveRights -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -PrincipalId $first.targetPrincipalId -TenantId $TenantId -Vaults $inst.vaults -ExtraScopes $ExtraScopes -PimGroupNames $PimGroupNames
        # the sign-in front's federated credential trusts the WEB identity by its object id -> it moves with the web role
        $ficSrc = @(); $ficTo = @()
        if ($role -eq 'web') {
            $ficSrc = @(Read-PimIdentityMoveFics -Graph $Graph -PrincipalIds @($sources | ForEach-Object { "$($_.principalId)" }))
            $ficTgt = @(if ("$($first.targetPrincipalId)".Trim()) { Read-PimIdentityMoveFics -Graph $Graph -PrincipalIds @("$($first.targetPrincipalId)") })
            $ficTo = @($ficSrc | Where-Object { $fs = $_; -not @($ficTgt | Where-Object { $_.appObjectId -ieq $fs.appObjectId -and $_.issuer -ieq $fs.issuer }).Count } | Sort-Object appObjectId -Unique)
        }
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
                $heldO = @(@($ps.owned) | Where-Object { $o2 = $_; @(@($tr.owned) | Where-Object { "$($_.id)" -ieq "$($o2.id)" }).Count }).Count
                if (($heldA + $heldG + $heldM + $heldD + $heldK + $heldO) -gt 0) { $removable = $true }
            }
        }
        $state = if (@($rr | Where-Object { -not $_.signsInAsTarget }).Count) { 'move' } elseif ($removable) { 'cleanup' } else { 'ok' }
        $roles.Add([pscustomobject]@{
            role = $role; target = $target; targetExists = $first.targetExists; targetId = $first.targetId; targetClientId = $first.targetClientId; targetPrincipalId = $first.targetPrincipalId
            resources = $rr; sources = $sources; state = $state
            sourceRights = $sr; perSource = $perSource; targetRights = $tr
            toCopy = @{ graph = @($c.graph); groups = @(@($c.groups) | ForEach-Object { [pscustomobject]@{ id = "$_"; displayName = $grpNames["$_".ToLowerInvariant()] } }); dirRoles = @(Get-PimIdentityMoveDirRolesMissing -Source $sr.dirRoles -Target $tr.dirRoles)
                        azure = $(if ($SupportHasRootAccess) { @($c.azure) } else { $azNorm }); azureRootCustomer = $(if ($SupportHasRootAccess) { @() } else { $azRoot }); kv = @(Get-PimIdentityMoveKvMissing -Source $sr.kv -Target $tr.kv)
                        owned = @(@($sr.owned) | Where-Object { $o1 = $_; -not @(@($tr.owned) | Where-Object { "$($_.id)" -ieq "$($o1.id)" }).Count } | Sort-Object id -Unique)
                        fic = @($ficTo) }
            ficSources = @($ficSrc)
            customerSteps = @($cust.ToArray()); notCopied = @($notCopied.ToArray())
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
          [AllowEmptyCollection()][string[]]$Detach = @(), [string[]]$ClientIdEnvNames = @('PIM_ManagedIdentityClientId'), [switch]$DryRun,
          # a container app / job PATCH is long-running: the GET straight after it can still show the OLD state (internal
          # ca-pim-rfa 2026-11-08 07:11Z: switched, read back as not). Read back until the resource is no longer in progress and
          # matches, up to -ReadBackTries reads, -ReadBackWaitSeconds apart.
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10)
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
    # READ BACK (until no longer in progress and matching; see -ReadBackTries)
    $tries = [Math]::Max(1, $ReadBackTries)
    for ($try = 1; $try -le $tries; $try++) {
    if ($try -gt 1) { & $Sleep $ReadBackWaitSeconds }
    $b = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
    $bps = "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $b 'properties') 'provisioningState')"
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
    $inProgress = $bps -match '^(?i)(InProgress|Updating|Pending|Accepted|Provisioning|Creating)$'
    if (-not $bad.Count -and -not $inProgress) { break }
    }
    if ($bps -match '^(?i)Failed$') { $bad.Add("its update ended in provisioning state Failed") }
    if ($bad.Count) { throw "read-back of $(@($ResourceId -split '/')[-1]) ($tries read(s), last state '$bps'): $($bad -join '; ')" }
    if ($inProgress) { throw "read-back of $(@($ResourceId -split '/')[-1]): still '$bps' after $tries read(s) -- NOT confirmed" }
    return @{ changed = $true; detail = ($changes -join '; ') }
}

# ---------------------------------------------------------------------------------------------------------- default seams
function Merge-PimIdentityMoveDbInitPrincipals {
    <#
      PURE. Add one principal to the database job's PIM_DBINIT_PRINCIPALS JSON array without dropping any that are there (the
      same rule as the updater's Merge-PimDbInitPrincipals, duplicated here so the engine library does not load setup code).
      Same name + same appId + same roles = unchanged; same name otherwise = replaced (a rebuilt identity). Always an ARRAY.
      Returns @{ json; changed }.
    #>
    # -SigninOwner (PIM item 21): the merged principal OWNS schema signin (the web identity -- the sign-in front's key ring); the
    # flag moves to it: no other principal in the list keeps it (a schema has one owner; the job refuses two)
    param([AllowEmptyString()][AllowNull()][string]$Json, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @(), [switch]$SigninOwner)
    $list = New-Object System.Collections.Generic.List[object]
    if ("$Json".Trim()) {
        $parsed = $null
        try { $parsed = ("$Json" | ConvertFrom-Json) } catch { throw "PIM_DBINIT_PRINCIPALS of the database job is not valid JSON -- refusing to overwrite it: $($_.Exception.Message)" }
        foreach ($p in @($parsed)) {
            if ($p -and "$($p.name)".Trim()) {
                $e = [ordered]@{ name = "$($p.name)"; appId = "$($p.appId)" }
                $pr = @($p.roles | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
                if ($pr.Count) { $e['roles'] = $pr }
                if ($p.PSObject.Properties['signinOwner'] -and [bool]$p.signinOwner) { $e['signinOwner'] = $true }   # PIM item 21: KEPT (the sign-in front's schema owner)
                [void]$list.Add($e)
            }
        }
    }
    $want = @($Roles | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
    $changed = $true
    $hit = @($list | Where-Object { "$($_.name)" -ieq $Name })
    $sameRoles = { param($e) $have = @(if ($e.Contains('roles')) { $e['roles'] }); (@($have | Sort-Object) -join ',') -eq (@($want | Sort-Object) -join ',') }
    $soSame = (-not $SigninOwner) -or ($hit.Count -and $hit[0].Contains('signinOwner') -and -not @($list | Where-Object { "$($_.name)" -ine $Name -and $_.Contains('signinOwner') }).Count)
    if ($hit.Count -and "$($hit[0].appId)" -ieq $AppId -and (& $sameRoles $hit[0]) -and $soSame) { $changed = $false }
    elseif ($hit.Count) { $hit[0].appId = $AppId; if ($want.Count) { $hit[0]['roles'] = $want } elseif ($hit[0].Contains('roles')) { $hit[0].Remove('roles') } }
    else { $e = [ordered]@{ name = $Name; appId = $AppId }; if ($want.Count) { $e['roles'] = $want }; [void]$list.Add($e) }
    if ($SigninOwner) {
        # rebuilt, never edited in place: the flag on the merged principal only (a schema has one owner)
        $re = New-Object System.Collections.Generic.List[object]
        foreach ($x in $list.ToArray()) {
            $n2 = [ordered]@{}; foreach ($k in @($x.Keys)) { if ("$k" -ne 'signinOwner') { $n2["$k"] = $x["$k"] } }
            if ("$($x['name'])" -ieq $Name) { $n2['signinOwner'] = $true }
            [void]$re.Add($n2)
        }
        $list = $re
    }
    $out = ConvertTo-Json -Compress -Depth 5 -InputObject @($list.ToArray())
    if ($out -notmatch '^\s*\[') { $out = "[$out]" }
    return @{ json = $out; changed = $changed }
}

function Start-PimIdentityMoveJob {
    <#
      ACA-START-OVERRIDE: ONE execution of a job through the shared, override-free start (Start-PimAcaJobExecution: the empty
      body, a bounded wait on a 409 while the job is still provisioning). Per-run work never travels in the start call: it is
      in the job definition the caller wrote and read back first. Returns @{ ok; execution; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $idm = [regex]::Match("$JobId", '^/subscriptions/(?<s>[^/]+)/resourceGroups/(?<g>[^/]+)/providers/Microsoft\.App/jobs/(?<n>[^/]+)$', 'IgnoreCase')
    if (-not $idm.Success) { return @{ ok = $false; execution = ''; reason = "not a Container Apps job id: $JobId" } }
    $mvApiVer = (Get-PimIdentityMoveApi).aca
    $mvArm = $Arm
    # No .GetNewClosure() (Test-PimHybridWorker L19: a closure cannot see dot-sourced functions): the block runs inside
    # Start-PimAcaJobExecution, called from here, so $mvArm / $mvApiVer resolve through this function's scope.
    $inv = { param($p) & $mvArm 'POST' "$p`?api-version=$mvApiVer" @{} }
    return (Start-PimAcaJobExecution -SubscriptionId $idm.Groups['s'].Value -ResourceGroup $idm.Groups['g'].Value -Name $idm.Groups['n'].Value -Invoke $inv -Sleep $Sleep)
}

function Invoke-PimIdentityMoveDefaultDbInit {
    <#
      The SQL step through the in-network database job. The job is started with the EMPTY body (ACA-START-OVERRIDE: a start
      with a container override needs Microsoft.App/jobs/write and is refused), so the one user travels where the job reads its
      work: it is MERGED into the job definition's PIM_DBINIT_PRINCIPALS (the list the job converges on every run; every
      principal already there is kept, as the updater does), the definition is READ BACK, then ONE execution is started through
      the shared start. The job exits 0 only when every listed user -- the moved one included -- was READ BACK with the right
      SID and roles. Returns @{ ok; detail; execution }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][string]$UserName,
          [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @(), [switch]$SigninOwner, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$MaxPolls = 60)
    $api = Get-PimIdentityMoveApi
    $jobPath = "$JobId`?api-version=$($api.aca)"
    $jobName = @($JobId -split '/')[-1]
    $job = Invoke-PimIdentityMoveGet -Seam $Arm -Path $jobPath
    if (-not $job) { return @{ ok = $false; detail = "the database job $jobName is not there" } }
    $tpl = Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'properties') 'template'
    $conts = New-Object System.Collections.Generic.List[object]; $changed = $false
    foreach ($c in @(Get-PimIdentityMoveField $tpl 'containers')) {
        if (-not $c) { continue }
        $envL = New-Object System.Collections.Generic.List[object]; $had = $false
        foreach ($e in @(Get-PimIdentityMoveField $c 'env')) {
            if (-not $e) { continue }
            if ("$(Get-PimIdentityMoveField $e 'name')" -ne 'PIM_DBINIT_PRINCIPALS') { $envL.Add($e); continue }
            $had = $true
            $m = Merge-PimIdentityMoveDbInitPrincipals -Json "$(Get-PimIdentityMoveField $e 'value')" -Name $UserName -AppId $AppId -Roles $Roles -SigninOwner:$SigninOwner
            if ($m.changed) { $changed = $true }
            $envL.Add([pscustomobject]@{ name = 'PIM_DBINIT_PRINCIPALS'; value = $m.json })
        }
        if (-not $had) { $changed = $true; $envL.Add([pscustomobject]@{ name = 'PIM_DBINIT_PRINCIPALS'; value = (Merge-PimIdentityMoveDbInitPrincipals -Json '' -Name $UserName -AppId $AppId -Roles $Roles -SigninOwner:$SigninOwner).json }) }
        $h = [ordered]@{}
        if ($c -is [System.Collections.IDictionary]) { foreach ($k in $c.Keys) { $h[$k] = $c[$k] } } else { foreach ($pp in $c.PSObject.Properties) { $h[$pp.Name] = $pp.Value } }
        $h['env'] = @($envL.ToArray())
        $conts.Add([pscustomobject]$h)
    }
    if (-not $conts.Count) { return @{ ok = $false; detail = "the database job $jobName has no container" } }
    if ($changed) {
        # the job DEFINITION (Microsoft.App/jobs/write, which the mover already uses for the switch), never the start call
        $tplH = [ordered]@{}
        if ($tpl -is [System.Collections.IDictionary]) { foreach ($k in $tpl.Keys) { $tplH[$k] = $tpl[$k] } } else { foreach ($pp in $tpl.PSObject.Properties) { $tplH[$pp.Name] = $pp.Value } }
        $tplH['containers'] = @($conts.ToArray())
        [void](& $Arm 'PATCH' $jobPath @{ properties = @{ template = [pscustomobject]$tplH } })
    }
    # READ BACK: every container of the job lists the user with this app id before the job is started
    $back = Invoke-PimIdentityMoveGet -Seam $Arm -Path $jobPath
    foreach ($c in @(Get-PimIdentityMoveField (Get-PimIdentityMoveField (Get-PimIdentityMoveField $back 'properties') 'template') 'containers')) {
        if (-not $c) { continue }
        $v = @(@(Get-PimIdentityMoveField $c 'env') | Where-Object { $_ -and "$(Get-PimIdentityMoveField $_ 'name')" -eq 'PIM_DBINIT_PRINCIPALS' } | ForEach-Object { "$(Get-PimIdentityMoveField $_ 'value')" })
        $okList = $false
        if ($v.Count) {
            try {
                $listed = ($v[0] | ConvertFrom-Json)   # PS 5.1 emits a JSON array as ONE object: assign, then enumerate
                foreach ($x in @($listed)) { if ($x -and "$($x.name)" -ieq $UserName -and "$($x.appId)" -ieq $AppId -and (-not $SigninOwner -or ($x.PSObject.Properties['signinOwner'] -and [bool]$x.signinOwner))) { $okList = $true } }
            } catch { $okList = $false }
        }
        if (-not $okList) { return @{ ok = $false; detail = "the database job $jobName does not list $UserName ($AppId) in PIM_DBINIT_PRINCIPALS on read-back -- not started" } }
    }
    $st = Start-PimIdentityMoveJob -Arm $Arm -JobId $JobId -Sleep $Sleep
    $exe = "$($st.execution)"
    if (-not $st.ok -or -not $exe) { return @{ ok = $false; detail = "the database job did not start$(if ($st.reason -and $st.reason -ne 'started') { ': ' + $st.reason } else { ' (no execution name returned)' })" } }
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
          [string[]]$StartJobRoles = @('engine'), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$MaxPolls = 40,
          # item 21 (c): the WEB proof is the hosted front itself -- seam: param($url) -> @{ status; error }
          # (no direct HTTP in this library -- H2: every call through a seam; the CALLER passes it. No seam = pending)
          [scriptblock]$Http)
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
                if ($h -eq 'Healthy' -and $Row.role -eq 'web') {
                    # !! item 21 (incident 2026-11-08 08:46Z): Healthy is NOT the web proof -- /healthz needs no SQL, and the moved
                    # Manager answered 500 on every page while its revision was Healthy. The proof is the front itself: / answers
                    # the sign-in (200 / 302 / 303, never 5xx) and /api/active-assignments without a session answers 401 / 403
                    # (never 500). Not reachable from here (a private install) = PENDING, never ok (the hosted smoke proves it).
                    $fq = "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField (Get-PimIdentityMoveField $ap 'configuration') 'ingress') 'fqdn')".Trim()
                    if (-not $fq) { return @{ ok = $false; pending = $true; detail = "revision $latest Healthy, but the app has no ingress name -- run the hosted smoke (Test-PimManagerHostedSmoke) to prove it" } }
                    if (-not $Http) { return @{ ok = $false; pending = $true; detail = "revision $latest Healthy; no HTTP seam to check the front https://$fq -- run the hosted smoke (Test-PimManagerHostedSmoke) to prove it" } }
                    $r1 = & $Http "https://$fq/"; $r2 = & $Http "https://$fq/api/active-assignments"
                    if (-not $r1.status -or -not $r2.status) { return @{ ok = $false; pending = $true; detail = "revision $latest Healthy; the front https://$fq is not reachable from here ($(@($r1.error, $r2.error) | Where-Object { $_ } | Select-Object -First 1)) -- run the hosted smoke there" } }
                    # the API refuses an anonymous call with 401 / 403, OR (the hosted sign-in front, 2026-11-08 internal) by
                    # sending it to the Entra sign-in: 302 / 303 whose Location is https://login.microsoftonline.<cloud>/ only
                    $apiRefused = ($r2.status -in @(401, 403)) -or ($r2.status -in @(302, 303) -and "$($r2.location)" -match '^https://login\.microsoftonline\.[a-z.]+/')
                    if ($r1.status -ge 500 -or $r2.status -ge 500 -or $r1.status -notin @(200, 302, 303) -or -not $apiRefused) { return @{ ok = $false; pending = $false; detail = "revision $latest Healthy BUT the front answers / -> $($r1.status), /api/active-assignments -> $($r2.status)$(if ($r2.location) { ' to ' + ("$($r2.location)" -replace '\?.*$', '') }) (wanted 200/302/303 and 401/403 or a redirect to the Entra sign-in) -- e.g. the sign-in front's SQL state (schema signin)" } }
                    return @{ ok = $true; pending = $false; detail = "revision $latest Healthy ($rs), signs in as $ClientId; front / -> $($r1.status), /api -> $($r2.status)" }
                }
                if ($h -eq 'Healthy') { return @{ ok = $true; pending = $false; detail = "revision $latest Healthy ($rs), signs in as $ClientId" } }
            }
            & $Sleep 15
        }
        return @{ ok = $false; pending = $false; detail = 'the new revision did not become healthy in time' }
    }
    $job = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($Row.resourceId)`?api-version=$($api.aca)"
    if (-not (& $envOk (Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'properties') 'template'))) { return @{ ok = $false; pending = $false; detail = "the job definition does not sign in as $ClientId" } }
    if ($StartJobRoles -contains $Row.role) {
        $st = Start-PimIdentityMoveJob -Arm $Arm -JobId "$($Row.resourceId)" -Sleep $Sleep
        $exe = "$($st.execution)"
        if (-not $st.ok -or -not $exe) { return @{ ok = $false; pending = $false; detail = "the job did not start$(if ($st.reason -and $st.reason -ne 'started') { ': ' + $st.reason })" } }
        $r = Wait-PimIdentityMoveJobExecution -Arm $Arm -JobId $Row.resourceId -Execution $exe -Sleep $Sleep -MaxPolls $MaxPolls
        return @{ ok = $r.ok; pending = $false; detail = "execution $exe $($r.status)" }
    }
    $since = $null
    $since = ConvertTo-PimIdentityMoveUtc (Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'systemData') 'lastModifiedAt')
    # !! a job that MODIFIES ITSELF (the updater writes its own job each run; a ring-1 test install's ca-pim-update 2026-11-08: three good runs
    # after the switch, each followed by its own change, so "a run since the last change" never came): when the last change
    # was made BY THE NEW IDENTITY (systemData.lastModifiedBy = its client id), the job has signed in as it and used its
    # Azure rights -- the run that made the change is the proof (the newest run that started before it, Succeeded).
    $modBy = "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $job 'systemData') 'lastModifiedBy')".Trim()
    if ($since -and $modBy -and $modBy -ieq "$ClientId".Trim()) {
        $exes0 = @(Get-PimIdentityMoveList -Seam $Arm -Path "$($Row.resourceId)/executions?api-version=$($api.aca)")
        $before = @($exes0 | Where-Object { $t = ConvertTo-PimIdentityMoveUtc (Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime'); $t -and $t -le $since } |
                    Sort-Object { ConvertTo-PimIdentityMoveUtc (Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime') } -Descending)
        $by = @($before | Where-Object { "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'status')" -in @('Succeeded', 'Failed', 'Stopped', 'Degraded') })
        if ($by.Count -and "$(Get-PimIdentityMoveField (Get-PimIdentityMoveField $by[0] 'properties') 'status')" -eq 'Succeeded') {
            return @{ ok = $true; pending = $false; detail = "execution $(Get-PimIdentityMoveField $by[0] 'name') Succeeded and then changed the job AS $ClientId (it signs in as the new identity)" }
        }
    }
    # the mover's OWN switch time wins when it is later: the job's lastModifiedAt can still show an EARLIER change right after
    # the switch (internal ca-pim-dbinit 2026-11-08 07:59Z: a 07:41Z run was taken as "after the switch")
    if ($script:PimIdentityMoveSwitchUtc -is [datetime] -and (-not $since -or $script:PimIdentityMoveSwitchUtc -gt $since)) { $since = $script:PimIdentityMoveSwitchUtc }
    $exes = @(Get-PimIdentityMoveList -Seam $Arm -Path "$($Row.resourceId)/executions?api-version=$($api.aca)")
    $after = @($exes | Where-Object {
        $t = ConvertTo-PimIdentityMoveUtc (Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime')
        $t -and $since -and $t -gt $since } | Sort-Object { ConvertTo-PimIdentityMoveUtc (Get-PimIdentityMoveField (Get-PimIdentityMoveField $_ 'properties') 'startTime') } -Descending)
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
          [string[]]$StartJobRoles = @('engine'), [switch]$DryRun, [switch]$NoCleanup,
          [scriptblock]$Http)   # item 21 (c): the web proof's HTTP seam -- passed by the caller (Move-PimIdentities.ps1); none = the web proof stays pending
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
    $dbJobFn = if ($DbInit) { $DbInit } else { { param($jobId, $userName, $appId, $roles, $signinOwner) Invoke-PimIdentityMoveDefaultDbInit -Arm $Arm -JobId $jobId -UserName $userName -AppId $appId -Roles $roles -SigninOwner:([bool]$signinOwner) -Sleep $Sleep } }
    $proveFn = if ($Prove) { $Prove } else { { param($row, $clientId) $pa = @{ Arm = $Arm; Row = $row; ClientId = $clientId; StartJobRoles = $StartJobRoles; Sleep = $Sleep }; if ($Http) { $pa['Http'] = $Http }; Invoke-PimIdentityMoveDefaultProve @pa } }
    $tgtName = $rp.target; $tgtId = "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$tgtName"
    $tgtPid = "$($rp.targetPrincipalId)"; $tgtCid = "$($rp.targetClientId)"
    $cur = ''
    try {
        # ------------------------------------------------------------------ 1 identity
        $cur = 'identity'
        if ($rp.state -eq 'move') {
            $idObj = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$tgtId`?api-version=$($api.msi)"
            if (-not $idObj) {
                # the ROLE'S OWN resource location first (an app / job that exists there is allowed there): the resource
                # group's location can be one a customer's "Allowed locations" policy refuses (a customer install
                # 2026-11-08: PUT id-pim-web -> 403 RequestDisallowedByPolicy "IAC: Allowed locations")
                $resLoc = "$(@($rp.resources | Where-Object { "$($_.location)".Trim() })[0].location)".Trim()
                $loc = if ($resLoc) { $resLoc } elseif ($Plan.location) { $Plan.location } else { '' }
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
        # a NEW managed identity's service principal reaches the directory seconds to minutes after ARM returns it (internal
        # id-pim-engine 2026-11-08 07:28Z: the first app-role grant got 404 Request_ResourceNotFound) -- wait until Graph sees it
        if (-not $DryRun -and $tgtPid -and (@($rp.toCopy.graph).Count + @($rp.toCopy.groups).Count + @($rp.toCopy.dirRoles).Count)) {
            $spSeen = $false
            for ($spTry = 1; $spTry -le 18; $spTry++) {
                if ($spTry -gt 1) { & $Sleep 10 }
                if (Invoke-PimIdentityMoveGet -Seam $Graph -Path "/servicePrincipals/$tgtPid`?`$select=id") { $spSeen = $true; break }
            }
            if (-not $spSeen) { throw "the service principal of $tgtName ($tgtPid) is not visible in the directory after 18 reads (~3 min) -- re-run this role later" }
        }
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
                $r = Invoke-PimIdentityMoveGraphAdd -Graph $Graph -Path "/servicePrincipals/$tgtPid/appRoleAssignments" -Body @{ principalId = $tgtPid; resourceId = $g.resourceId; appRoleId = $g.appRoleId }
                $back = Wait-PimIdentityMoveGraphBack -Sleep $Sleep -Read { @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$tgtPid/appRoleAssignments" | Where-Object { "$(Get-PimIdentityMoveField $_ 'resourceId')" -ieq $g.resourceId -and "$(Get-PimIdentityMoveField $_ 'appRoleId')" -ieq $g.appRoleId }) }
                if (-not $back.Count) { throw "$what was granted to $tgtName but does not read back" }
                $aid = "$(Get-PimIdentityMoveField $back[0] 'id')"
                & $step 'graph' "granted $tgtName $what" 'read back' "Invoke-PimGraph -Method DELETE -Path '/servicePrincipals/$tgtPid/appRoleAssignments/$aid'"
                $rec.copied.Add("graph: $what")
            }
            foreach ($g in @($rp.toCopy.groups)) {
                if ($DryRun) { & $step 'graph' "would add $tgtName to the PIM group $($g.displayName)" '' ''; continue }
                [void](Invoke-PimIdentityMoveGraphAdd -Graph $Graph -Path "/groups/$($g.id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$tgtPid" })
                $back = Wait-PimIdentityMoveGraphBack -Sleep $Sleep -Read { @(Get-PimIdentityMoveList -Seam $Graph -Path "/servicePrincipals/$tgtPid/memberOf/microsoft.graph.group?`$select=id,displayName" | Where-Object { "$(Get-PimIdentityMoveField $_ 'id')" -ieq $g.id }) }
                if (-not $back.Count) { throw "$tgtName was added to $($g.displayName) but the membership does not read back" }
                & $step 'graph' "added $tgtName to the PIM group $($g.displayName)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/groups/$($g.id)/members/$tgtPid/`$ref'"
                $rec.copied.Add("group: $($g.displayName)")
            }
            foreach ($d in @($rp.toCopy.dirRoles)) {
                if ($DryRun) { & $step 'graph' "would assign $tgtName the directory role $($d.roleDefinitionId) at $($d.directoryScopeId)" '' ''; continue }
                $r = Invoke-PimIdentityMoveGraphAdd -Graph $Graph -Path '/roleManagement/directory/roleAssignments' -Body @{ principalId = $tgtPid; roleDefinitionId = $d.roleDefinitionId; directoryScopeId = $(if ($d.directoryScopeId) { $d.directoryScopeId } else { '/' }) }
                $back = Wait-PimIdentityMoveGraphBack -Sleep $Sleep -Read { @(Get-PimIdentityMoveList -Seam $Graph -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$tgtPid'" | Where-Object { "$(Get-PimIdentityMoveField $_ 'roleDefinitionId')" -ieq $d.roleDefinitionId }) }
                if (-not $back.Count) { throw "the directory role $($d.roleDefinitionId) does not read back on $tgtName" }
                & $step 'graph' "assigned $tgtName the directory role $($d.roleDefinitionId)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/roleManagement/directory/roleAssignments/$(Get-PimIdentityMoveField $back[0] 'id')'"
                $rec.copied.Add("directory role: $($d.roleDefinitionId)")
            }
            foreach ($ow in @($rp.toCopy.owned)) {
                if ($DryRun) { & $step 'graph' "would add $tgtName as owner of the app registration $($ow.displayName)" '' ''; continue }
                [void](Invoke-PimIdentityMoveGraphAdd -Graph $Graph -Path "/applications/$($ow.id)/owners/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$tgtPid" })
                $back = Wait-PimIdentityMoveGraphBack -Sleep $Sleep -Read { @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications/$($ow.id)/owners?`$select=id" | Where-Object { "$(Get-PimIdentityMoveField $_ 'id')" -ieq $tgtPid }) }
                if (-not $back.Count) { throw "$tgtName was added as owner of $($ow.displayName) but does not read back as one" }
                & $step 'graph' "added $tgtName as owner of the app registration $($ow.displayName)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/applications/$($ow.id)/owners/$tgtPid/`$ref'"
                $rec.copied.Add("owner: $($ow.displayName)")
            }
            foreach ($fc in @($rp.toCopy.fic)) {
                $fn = ("signin-front-$tgtName" -replace '[^A-Za-z0-9-]', '-')
                if ($DryRun) { & $step 'graph' "would add the federated credential $fn for $tgtName on $($fc.appName) (the sign-in front signs in as it)" '' ''; continue }
                [void](Invoke-PimIdentityMoveGraphAdd -Graph $Graph -Path "/applications/$($fc.appObjectId)/federatedIdentityCredentials" -Body @{ name = $fn; issuer = $fc.issuer; subject = $tgtPid; audiences = @($fc.audiences); description = "PIM Manager sign-in front: the web identity $tgtName is the client credential -- no secret (NAM-03 move)." })
                $back = Wait-PimIdentityMoveGraphBack -Sleep $Sleep -Read { @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications/$($fc.appObjectId)/federatedIdentityCredentials" | Where-Object { "$(Get-PimIdentityMoveField $_ 'subject')" -ieq $tgtPid -and "$(Get-PimIdentityMoveField $_ 'issuer')" -ieq $fc.issuer }) }
                if (-not $back.Count) { throw "the federated credential for $tgtName on $($fc.appName) does not read back" }
                & $step 'graph' "added the federated credential $fn for $tgtName on $($fc.appName)" 'read back' "Invoke-PimGraph -Method DELETE -Path '/applications/$($fc.appObjectId)/federatedIdentityCredentials/$(Get-PimIdentityMoveField $back[0] 'id')'"
                $rec.copied.Add("federated credential: $($fc.appName)")
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
                    $r = & $dbJobFn $rp.sql.jobId $tgtName $tgtCid @($rp.sql.roles) ($Role -eq 'web')   # item 21: the web identity OWNS schema signin (the sign-in front)
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
                if (-not $DryRun) { $script:PimIdentityMoveSwitchUtc = [datetime]::UtcNow }
                $sw = Set-PimIdentityMoveSwitch -Arm $Arm -ResourceId $row.resourceId -FromIds $fromIds -FromClientIds $fromCids -ToId $tgtId -ToClientId $tgtCid -ClientIdEnvNames $envNames -DryRun:$DryRun -Sleep $Sleep
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
        # the sign-in front's federated credential of the OLD identity goes only where the target's reads back on the same app
        foreach ($fc in @($RolePlan.ficSources | Where-Object { "$($_.subject)" -ieq "$($s.principalId)" })) {
            $have = @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications/$($fc.appObjectId)/federatedIdentityCredentials" | Where-Object { "$(Get-PimIdentityMoveField $_ 'subject')" -ieq "$TargetPrincipalId" -and "$(Get-PimIdentityMoveField $_ 'issuer')" -ieq $fc.issuer })
            if (-not $have.Count) { $rec.kept.Add("$($s.name): federated credential $($fc.name) on $($fc.appName) kept -- $($RolePlan.target) has none there"); continue }
            [void](& $Graph 'DELETE' "/applications/$($fc.appObjectId)/federatedIdentityCredentials/$($fc.id)" $null)
            & $Step 'cleanup' "removed the federated credential $($fc.name) of $($s.name) on $($fc.appName)" 'removed' "Invoke-PimGraph -Method POST -Path '/applications/$($fc.appObjectId)/federatedIdentityCredentials' -Body @{ name = '$($fc.name)'; issuer = '$($fc.issuer)'; subject = '$($s.principalId)'; audiences = @('api://AzureADTokenExchange') }"
            $rec.removed.Add("$($s.name): federated credential on $($fc.appName)")
        }

        if ($s.kind -eq 'user') {
            $still = @($users["$($s.id)".ToLowerInvariant()] | Where-Object { $_ })
            if ($still.Count) { $rec.kept.Add("$($s.name): rights kept -- still used by $($still -join ', ')"); continue }
        }
        $sr = $RolePlan.perSource["$($s.principalId)".ToLowerInvariant()]
        if (-not $sr) { continue }
        # An old identity loses ALL its rights after the proof (framework 12.11c ruling (b): names 'ok' only when no old
        # identity holds rights; Invardia 2026-11-08): a SHARED id-pim-* identity once nothing uses it (also what no role took
        # over, -NeedOnly), and the role's own system identity (it signs in for nothing once switched). Root rights without
        # root access stay a customer step; non-PIM groups are never read, so never touched.
        $orphan = $true
        $rec.removed.Add("$($s.name): no longer used by the role -- every right it holds is removed")
        $haveA = @{}; foreach ($a in @($now.azure)) { $haveA[(("$($a.roleDefinitionId)" -replace '^.*/roleDefinitions/', '').ToLowerInvariant() + '|' + "$($a.scope)".TrimEnd('/').ToLowerInvariant())] = $true }
        foreach ($a in @($sr.azure)) {
            $k = ("$($a.roleDefinitionId)" -replace '^.*/roleDefinitions/', '').ToLowerInvariant() + '|' + "$($a.scope)".TrimEnd('/').ToLowerInvariant()
            if (-not $orphan -and -not $haveA.ContainsKey($k)) { $rec.kept.Add("$($s.name): Azure role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope) kept -- $($RolePlan.target) does not hold it"); continue }
            if ($a.root -and -not $Plan.supportHasRootAccess) { $rec.customerSteps.Add([pscustomobject]@{ when = 'after the proof'; what = "remove the old identity's role at the tenant root"; command = (Get-PimIdentityMoveCustomerCommand -Action remove -PrincipalId $s.principalId -RoleDefinitionId $a.roleDefinitionId -Scope $a.scope) }); continue }
            [void](& $Arm 'DELETE' "$($a.id)?api-version=$($api.auth)" $null)
            if (Invoke-PimIdentityMoveGet -Seam $Arm -Path "$($a.id)?api-version=$($api.auth)") { throw "$($s.name): the Azure role $($a.id) is still there after the delete" }
            & $Step 'cleanup' "removed from $($s.name): Azure role $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope)" 'read back: gone' "Invoke-PimArm -Method PUT -Path '$($a.id)?api-version=$($api.auth)' -Body @{ properties = @{ roleDefinitionId = '$($a.roleDefinitionId)'; principalId = '$($s.principalId)'; principalType = 'ServicePrincipal' } }"
            $rec.removed.Add("$($s.name): azure $(@("$($a.roleDefinitionId)" -split '/')[-1]) at $($a.scope)")
        }
        $haveG = @{}; foreach ($g in @($now.graph)) { $haveG["$($g.resourceId)|$($g.appRoleId)".ToLowerInvariant()] = $true }
        foreach ($g in @($sr.graph)) {
            if (-not $orphan -and -not $haveG.ContainsKey("$($g.resourceId)|$($g.appRoleId)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): app role $($g.appRoleId) kept -- the target does not hold it"); continue }
            [void](& $Graph 'DELETE' "/servicePrincipals/$($s.principalId)/appRoleAssignments/$($g.id)" $null)
            & $Step 'cleanup' "removed from $($s.name): app role $($g.appRoleId)" 'removed' "Invoke-PimGraph -Method POST -Path '/servicePrincipals/$($s.principalId)/appRoleAssignments' -Body @{ principalId = '$($s.principalId)'; resourceId = '$($g.resourceId)'; appRoleId = '$($g.appRoleId)' }"
            $rec.removed.Add("$($s.name): graph $($g.appRoleId)")
        }
        $haveM = @{}; foreach ($g in @($now.groups)) { $haveM["$($g.id)".ToLowerInvariant()] = $true }
        foreach ($g in @($sr.groups)) {
            if (-not $orphan -and -not $haveM.ContainsKey("$($g.id)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): $($g.displayName) membership kept -- the target is not a member"); continue }
            [void](& $Graph 'DELETE' "/groups/$($g.id)/members/$($s.principalId)/`$ref" $null)
            & $Step 'cleanup' "removed $($s.name) from the PIM group $($g.displayName)" 'removed' "Invoke-PimGraph -Method POST -Path '/groups/$($g.id)/members/`$ref' -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/$($s.principalId)' }"
            $rec.removed.Add("$($s.name): group $($g.displayName)")
        }
        $haveD = @{}; foreach ($d in @($now.dirRoles)) { $haveD["$($d.roleDefinitionId)".ToLowerInvariant()] = $true }
        foreach ($d in @($sr.dirRoles)) {
            if (-not $orphan -and -not $haveD.ContainsKey("$($d.roleDefinitionId)".ToLowerInvariant())) { $rec.kept.Add("$($s.name): directory role $($d.roleDefinitionId) kept"); continue }
            [void](& $Graph 'DELETE' "/roleManagement/directory/roleAssignments/$($d.id)" $null)
            & $Step 'cleanup' "removed from $($s.name): directory role $($d.roleDefinitionId)" 'removed' "Invoke-PimGraph -Method POST -Path '/roleManagement/directory/roleAssignments' -Body @{ principalId = '$($s.principalId)'; roleDefinitionId = '$($d.roleDefinitionId)'; directoryScopeId = '$($d.directoryScopeId)' }"
            $rec.removed.Add("$($s.name): directory role $($d.roleDefinitionId)")
        }
        foreach ($k in @($sr.kv)) {
            $tk = @(@($now.kv) | Where-Object { "$($_.vaultId)" -ieq "$($k.vaultId)" })
            if (-not $orphan -and @(Get-PimIdentityMoveKvMissing -Source @($k) -Target $tk).Count) { $rec.kept.Add("$($s.name): access policy on $($k.vaultName) kept -- the target does not hold it all"); continue }
            [void](& $Arm 'PUT' "$($k.vaultId)/accessPolicies/remove?api-version=$($api.kv)" @{ properties = @{ accessPolicies = @(@{ tenantId = $(if ($k.tenantId) { $k.tenantId } else { $Plan.tenantId }); objectId = $s.principalId; permissions = $k.permissions }) } })
            & $Step 'cleanup' "removed $($s.name) from the access policy on $($k.vaultName)" 'removed' "Invoke-PimArm -Method PUT -Path '$($k.vaultId)/accessPolicies/add?api-version=$($api.kv)' -Body <the policy in this record>"
            $rec.removed.Add("$($s.name): kv $($k.vaultName)")
        }
        # app registration ownership: the old identity leaves as owner ONLY where the target reads back as an owner
        foreach ($ow in @($sr.owned)) {
            $own = @(Get-PimIdentityMoveList -Seam $Graph -Path "/applications/$($ow.id)/owners?`$select=id" | ForEach-Object { "$(Get-PimIdentityMoveField $_ 'id')".ToLowerInvariant() })
            if (-not ($own -contains "$TargetPrincipalId".ToLowerInvariant())) { $rec.kept.Add("$($s.name): owner of $($ow.displayName) kept -- $($RolePlan.target) is not an owner"); continue }
            [void](& $Graph 'DELETE' "/applications/$($ow.id)/owners/$($s.principalId)/`$ref" $null)
            & $Step 'cleanup' "removed $($s.name) as owner of the app registration $($ow.displayName)" 'removed' "Invoke-PimGraph -Method POST -Path '/applications/$($ow.id)/owners/`$ref' -Body @{ '@odata.id' = 'https://graph.microsoft.com/v1.0/directoryObjects/$($s.principalId)' }"
            $rec.removed.Add("$($s.name): owner of $($ow.displayName)")
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
