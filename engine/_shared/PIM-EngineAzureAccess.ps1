#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 95.2k -- "the engine's rights must follow its configuration, automatically" (owner 2026-10-07 at a
    customer: "dont do any manual chg" / "engine must automatically work"; build approved 2026-10-29).

.DESCRIPTION
    CONVERGE ENGINE ACCESS. From the Azure scopes the store DEFINES (PIM-Assignments-Azure-Resources.AzScope +
    PIM-Definitions-Resources.AzScope/Scope/ResourceScope -- exactly the scopes the AzRes / AzResPolicies providers read
    and write) work out the Azure role assignments the ENGINE identity (the tick's managed identity) needs, compare them
    with what it holds (assignments at the scope AND inherited from above it), and either
      * APPLY the missing ones (setup scripts run by a PERSON with the rights: Confirm-PimInstall's repair, which is the
        last step of Install-PimManager, Invoke-PimDeployAll and Invoke-PimMspBuild), read back, never fatal; or
      * REPORT them (the in-container updater, every update -- read-only: the updater may not grant roles).

    WHICH ROLE, AND WHY NOT A SMALLER ONE.
      The AzRes provider PUTs {scope}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{id} and
      .../roleAssignmentScheduleRequests/{id} (create / extend / remove of an eligible or active assignment), and the
      AzResPolicies provider PATCHes {scope}/providers/Microsoft.Authorization/roleManagementPolicies/{id}. Both are
      Microsoft.Authorization/* write actions. 'User Access Administrator' (Microsoft.Authorization/*) covers them;
      'Role Based Access Control Administrator' does NOT (its actions are roleAssignments/write + /delete + */read only:
      no roleManagementPolicies/write, so every Azure role POLICY would stay refused). So the ONE role this step ever
      grants is User Access Administrator, at the defined scope. Owner is never granted (it would add every resource
      write in the scope); an Owner the customer gave is accepted as COVERING (it includes Microsoft.Authorization/*).

    RULES (each one is a test in tests/Test-PimEngineAzureAccess.ps1):
      * no Azure definitions -> nothing to do ('not needed'); the engine touches only what is defined.
      * a defined scope already covered (UAA / Owner at it or ABOVE it -- the read is atScope(), so every assignment it
        returns applies at the scope, incl. one inherited from a management group or the tenant root) -> 'covered'.
      * a defined scope under another defined scope (a resource group under a defined subscription) -> covered by the
        parent's grant, never a second grant.
      * the tenant root management group as a defined scope -> 'opt-in': User Access Administrator at the ROOT stays the
        install's opt-in (-EngineAzureRootUserAccessAdmin, SEC-34). It is reported with the command, never granted here
        without that switch.
      * assignments that could not be read -> 'unknown' (never guessed as missing, never granted blind).
      * NEVER a remove. A grant this step made (description marker) at a scope no longer defined is reported 'not needed'
        and left in place -- removing a role assignment is a person's decision.
    PS 5.1 + 7, REST through a caller-supplied ARM seam, no modules, no az. ASCII.
#>

Set-StrictMode -Off
# SCRIPT-DOC-1 (framework 12.7 + 12.10 item 11): the fix command comes from the ONE command form in
# tools\setup\_PimScriptDoc.ps1 -- line 1 download, line 2 run (same load as PIM-PermissionHealth.ps1).
. (Join-Path $PSScriptRoot '..\..\tools\setup\_PimScriptDoc.ps1')

$script:PimEaaUaaGuid  = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'   # User Access Administrator
$script:PimEaaOwnerGuid = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'   # Owner (accepted as covering, never granted)
$script:PimEaaRole      = 'User Access Administrator'
$script:PimEaaApi       = '2022-04-01'
$script:PimEaaMarker    = 'PIM Manager: converge engine access (95.2k)'
$script:PimEaaZeroGuid  = '00000000-0000-0000-0000-000000000000'

function Get-PimEngineAzureGrantRole {
    <# PURE. The ONE role this step grants, with its guid. Anything else is refused by Assert-PimEngineAzureGrantRole. #>
    [pscustomobject]@{ name = $script:PimEaaRole; guid = $script:PimEaaUaaGuid }
}

function Assert-PimEngineAzureGrantRole {
    <# PURE. Throws unless -RoleGuid is User Access Administrator. The last guard before any PUT (never Owner). #>
    param([string]$RoleGuid)
    if ("$RoleGuid".Trim().ToLowerInvariant() -ne $script:PimEaaUaaGuid) {
        throw "converge engine access: refusing to grant role '$RoleGuid' -- only User Access Administrator is ever granted to the engine (never Owner)."
    }
}

function Get-PimEaaRowValue {
    param([object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
    }
    return ''
}

function ConvertTo-PimEngineAzureScope {
    <#
      PURE. A defined scope -> its canonical form, or '' when it is not a scope the engine can be granted at:
      '/subscriptions/<guid>[/...]' or '/providers/Microsoft.Management/managementGroups/<id>'. Template placeholders
      ('<...>', the all-zero subscription) are not scopes.
    #>
    param([AllowNull()][string]$Scope)
    $s = "$Scope".Trim()
    if (-not $s -or $s -match '[<>{}\s]') { return '' }
    if ($s.Length -gt 1) { $s = $s.TrimEnd('/') }
    if ($s -match '^(?i)/subscriptions/([0-9a-fA-F-]{36})(/.*)?$') {
        if ($Matches[1] -eq $script:PimEaaZeroGuid) { return '' }
        return ('/subscriptions/' + $Matches[1].ToLowerInvariant() + $(if ($Matches[2]) { $Matches[2] } else { '' }))
    }
    if ($s -match '^(?i)/providers/Microsoft\.Management/managementGroups/([^/]+)$') { return ('/providers/Microsoft.Management/managementGroups/' + $Matches[1]) }
    return ''
}

function Get-PimEngineAzureDefinedScopes {
    <#
      PURE. The Azure scopes the store defines: PIM-Assignments-Azure-Resources.AzScope (incl. Remove rows -- removing an
      assignment needs the same right) + PIM-Definitions-Resources.AzScope/Scope/ResourceScope. Unique (case-insensitive),
      management groups first, then shortest first. Returns @{ scopes = @(@{ scope; sources[] }); ignored = @(<raw values that are not a scope>) }.
    #>
    param([object[]]$AssignmentRows = @(), [object[]]$DefinitionRows = @())
    $map = [ordered]@{}; $ignored = New-Object System.Collections.Generic.List[string]
    $add = {
        param($raw, $src)
        if (-not "$raw".Trim()) { return }
        $c = ConvertTo-PimEngineAzureScope -Scope $raw
        if (-not $c) { if (-not $ignored.Contains("$raw".Trim())) { $ignored.Add("$raw".Trim()) }; return }
        $k = $c.ToLowerInvariant()
        if (-not $map.Contains($k)) { $map[$k] = @{ scope = $c; sources = New-Object System.Collections.Generic.List[string] } }
        if (-not $map[$k].sources.Contains($src)) { $map[$k].sources.Add($src) }
    }
    foreach ($r in @($AssignmentRows | Where-Object { $null -ne $_ })) { & $add (Get-PimEaaRowValue -Row $r -Names @('AzScope')) 'PIM-Assignments-Azure-Resources' }
    foreach ($r in @($DefinitionRows | Where-Object { $null -ne $_ })) { & $add (Get-PimEaaRowValue -Row $r -Names @('AzScope', 'Scope', 'ResourceScope')) 'PIM-Definitions-Resources' }
    # management groups first (a grant there is evaluated before the subscriptions it may cover), then shortest path first
    # (a subscription before its resource groups) -- the planner relies on parents coming first.
    $out = @($map.Values | ForEach-Object { [pscustomobject]@{ scope = $_.scope; sources = @($_.sources.ToArray()) } } |
             Sort-Object { if ($_.scope -like '/providers/Microsoft.Management/*') { 0 } else { 1 } }, { $_.scope.Length }, { $_.scope })
    [pscustomobject]@{ scopes = $out; ignored = @($ignored.ToArray()) }
}

function Test-PimEngineAzurePathCovers {
    <#
      PURE. Does a grant at -Parent apply to -Child BY PATH ALONE? Equal, '/', the tenant root management group (its id
      is the tenant id), or a path ancestor on a '/' boundary (a subscription over its resource groups). A management
      group other than the root is NOT provable from the path (its children are not in it) -> $false.
    #>
    param([string]$Parent, [string]$Child, [string]$TenantId)
    $p = "$Parent".Trim().TrimEnd('/').ToLowerInvariant(); $c = "$Child".Trim().TrimEnd('/').ToLowerInvariant()
    if ("$Parent".Trim() -eq '/') { return $true }
    if (-not $p -or -not $c) { return $false }
    if ($p -eq $c) { return $true }
    if ("$TenantId".Trim() -and $p -eq ("/providers/microsoft.management/managementgroups/" + "$TenantId".Trim().ToLowerInvariant())) { return $true }
    if ($p -like '/providers/microsoft.management/managementgroups/*') { return $false }
    return $c.StartsWith($p + '/')
}

function Get-PimEaaAssignmentFacts {
    param([object]$Assignment)
    $p = if ($Assignment.PSObject.Properties['properties'] -and $Assignment.properties) { $Assignment.properties } else { $Assignment }
    $rd = "$($p.roleDefinitionId)".Trim().TrimEnd('/')
    [pscustomobject]@{ scope = "$($p.scope)".Trim(); roleGuid = $(if ($rd) { ($rd -split '/')[-1].ToLowerInvariant() } else { '' })
                       description = "$($p.description)"; principalId = "$($p.principalId)".Trim(); id = "$($Assignment.id)" }
}

function Get-PimEngineAzureAccessPlan {
    <#
      PURE. -Scopes: Get-PimEngineAzureDefinedScopes' .scopes. -Held: scope (any casing) -> the engine's assignments that
      apply AT that scope (an atScope() read: at it or above it), or $null when they could not be read. -AllAssignments
      (optional): every assignment of the engine in the tenant, to find this step's own grants that are no longer needed.
      -IncludeRootUserAccessAdministrator: the install's opt-in (SEC-34) -- only then is the tenant root ever planned.
      Returns @{ needed; rows = @(@{ scope; action = add | covered | opt-in | unknown; role; reason; sources }); adds[];
                 notNeeded = @(@{ scope; id }); summary }.  Never an action 'remove', never a role other than UAA.
    #>
    param([object[]]$Scopes = @(), [hashtable]$Held = @{}, [object[]]$AllAssignments = $null, [string]$TenantId = '',
          [switch]$IncludeRootUserAccessAdministrator)
    $role = Get-PimEngineAzureGrantRole
    $covering = @($script:PimEaaUaaGuid, $script:PimEaaOwnerGuid)
    $rootScope = if ("$TenantId".Trim()) { "/providers/Microsoft.Management/managementGroups/$("$TenantId".Trim())" } else { '' }
    $heldL = @{}; foreach ($k in @($Held.Keys)) { $heldL["$k".Trim().TrimEnd('/').ToLowerInvariant()] = $Held[$k] }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Scopes | Where-Object { $_ })) {
        $sc = "$($s.scope)"; $src = @($s.sources)
        $mk = { param($a, $why) [pscustomobject]@{ scope = $sc; action = $a; role = $role.name; reason = $why; sources = $src } }
        # 1. under a defined scope that is already planned or covered -> the parent's grant covers it (never two grants)
        $parent = @($rows | Where-Object { $_.action -in 'add', 'covered' -and (Test-PimEngineAzurePathCovers -Parent $_.scope -Child $sc -TenantId $TenantId) -and $_.scope -ne $sc }) | Select-Object -First 1
        if ($parent) { $rows.Add((& $mk 'covered' "under $($parent.scope) ($(if ($parent.action -eq 'add') { 'granted there by this step' } else { 'covered there' }))")); continue }
        # 2. what the engine holds at / above it
        $k = $sc.ToLowerInvariant()
        # NOT `$list = if (...) { $heldL[$k] }`: a statement's output is enumerated, so an EMPTY list (read fine, nothing
        # held) came out as $null and every uncovered scope was planned 'unknown' instead of 'add' (test VM, 2026-10-29).
        $list = $null
        if ($heldL.ContainsKey($k)) { $list = $heldL[$k] }
        if ($null -eq $list) { $rows.Add((& $mk 'unknown' 'the engine''s role assignments at this scope could not be read')); continue }
        $hit = $null
        foreach ($a in @($list | Where-Object { $_ })) {
            $f = Get-PimEaaAssignmentFacts -Assignment $a
            if ($f.roleGuid -notin $covering) { continue }
            # It must APPLY at the scope: '/', the scope itself or a path ancestor (a subscription over its resource
            # groups), or a management group -- an atScope() read returns a management group only when it is at or above
            # the scope. A subscription / resource group assignment that is not a path ancestor never counts.
            $fs = $f.scope.TrimEnd('/').ToLowerInvariant()
            $applies = ($f.scope -eq '/') -or ($fs -like '/providers/microsoft.management/managementgroups/*') -or (Test-PimEngineAzurePathCovers -Parent $fs -Child $k -TenantId $TenantId)
            if (-not $applies) { continue }
            $hit = $f; break
        }
        if ($hit) {
            $rn = if ($hit.roleGuid -eq $script:PimEaaOwnerGuid) { 'Owner' } else { 'User Access Administrator' }
            $rows.Add((& $mk 'covered' "$rn at $(if ($hit.scope.TrimEnd('/') -ieq $sc) { 'this scope' } else { "$($hit.scope) (inherited)" })")); continue
        }
        # 3. missing. The tenant root itself stays the install's opt-in.
        if ($rootScope -and $sc -ieq $rootScope -and -not $IncludeRootUserAccessAdministrator) {
            $rows.Add((& $mk 'opt-in' 'User Access Administrator at the tenant root is opt-in (-EngineAzureRootUserAccessAdmin); not granted by this step')); continue
        }
        $rows.Add((& $mk 'add' 'defined in the store, not held at or above this scope'))
    }
    # 4. this step's own grants at scopes that are no longer defined -> reported, never removed
    $notNeeded = New-Object System.Collections.Generic.List[object]
    if ($null -ne $AllAssignments) {
        foreach ($a in @($AllAssignments | Where-Object { $_ })) {
            $f = Get-PimEaaAssignmentFacts -Assignment $a
            if ($f.description -ne $script:PimEaaMarker -or $f.roleGuid -ne $script:PimEaaUaaGuid) { continue }
            $still = @($rows | Where-Object { $_.scope -ieq $f.scope.TrimEnd('/') }).Count -gt 0
            if (-not $still) { $notNeeded.Add([pscustomobject]@{ scope = $f.scope; id = $f.id; reason = 'granted by this step for a scope the store no longer defines -- left in place (never removed automatically)' }) }
        }
    }
    $adds = @($rows | Where-Object { $_.action -eq 'add' } | ForEach-Object { $_.scope })
    $cnt = { param($a) @($rows | Where-Object { $_.action -eq $a }).Count }
    $summary = if (-not $rows.Count) { 'no Azure scope is defined -- the engine needs no Azure role management right (nothing to do)' }
               else { "$($rows.Count) defined Azure scope(s): $(& $cnt 'covered') covered, $($adds.Count) to grant, $(& $cnt 'opt-in') opt-in, $(& $cnt 'unknown') not readable" }
    [pscustomobject]@{ needed = [bool]$rows.Count; rows = @($rows.ToArray()); adds = $adds; notNeeded = @($notNeeded.ToArray()); summary = $summary }
}

function Get-PimEngineAzureAccessFixCommand {
    <#
      PURE. The exact grant for the right person (an Owner / User Access Administrator of those scopes): the published,
      self-contained Grant-PimEnginePermissions.ps1 (REST + browser sign-in, no modules; framework rule 3).
    #>
    param([string]$TenantId, [string]$EngineObjectId, [string[]]$Scopes = @())
    $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { '<tenant id>' }
    $oid = if ("$EngineObjectId".Trim()) { "$EngineObjectId".Trim() } else { '<engine object id>' }
    $specs = @(@($Scopes) | Where-Object { "$_".Trim() } | ForEach-Object { "'$($script:PimEaaRole)@$("$_".Trim())'" }) -join ','
    if (-not $specs) { return '' }
    $run = ".\Grant-PimEnginePermissions.ps1 -TenantId '$tid' -EngineObjectId '$oid' -AzureRoleAssignments $specs"
    return ((Get-PimSupportScriptCommand -Script 'Grant-PimEnginePermissions' -Run @($run)) -join "`n")
}

function Get-PimEaaList {
    # One ARM GET through the seam, following nextLink. Throws on a failed read (the caller makes it 'unknown').
    param([scriptblock]$Arm, [string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $p = $Path; $guard = 0
    while ($p -and $guard -lt 50) {
        $guard++
        $r = & $Arm 'GET' $p $null
        if ($null -eq $r) { break }
        if ($r.PSObject.Properties['value']) { foreach ($v in @($r.value)) { if ($v) { $out.Add($v) } } } else { foreach ($v in @($r)) { if ($v) { $out.Add($v) } } }
        $p = if ($r.PSObject.Properties['nextLink']) { "$($r.nextLink)".Trim() } else { '' }
    }
    return @($out.ToArray())
}

function Read-PimEngineAzureHeld {
    <#
      READ-ONLY. For each scope: GET {scope}/providers/Microsoft.Authorization/roleAssignments with
      $filter=atScope() and assignedTo('<engine oid>') -- the engine's assignments AT or ABOVE the scope (incl. the ones
      inherited from management groups and the tenant root). -Arm { param($method, $path, $body) }. Never writes.
      Returns @{ held = @{ scope -> list | $null }; errors = @{ scope -> message } }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [object[]]$Scopes = @(), [Parameter(Mandatory)][string]$EngineObjectId)
    $held = @{}; $errors = @{}
    $f = "atScope()%20and%20assignedTo('{0}')" -f "$EngineObjectId".Trim()
    foreach ($s in @($Scopes | Where-Object { $_ })) {
        $sc = if ($s -is [string]) { $s } else { "$($s.scope)" }
        try { $held[$sc] = @(Get-PimEaaList -Arm $Arm -Path ("{0}/providers/Microsoft.Authorization/roleAssignments?`$filter={1}&api-version={2}" -f $sc, $f, $script:PimEaaApi)) }
        catch { $held[$sc] = $null; $errors[$sc] = ((("$($_.Exception.Message)") -split "`n")[0]).Trim() }
    }
    [pscustomobject]@{ held = $held; errors = $errors }
}

function Read-PimEngineAzureAllAssignments {
    <# READ-ONLY. Every assignment of the engine in the tenant (assignedTo at the tenant root), or $null when unreadable. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [string]$TenantId, [Parameter(Mandatory)][string]$EngineObjectId)
    if (-not "$TenantId".Trim()) { return $null }
    try { return @(Get-PimEaaList -Arm $Arm -Path ("/providers/Microsoft.Management/managementGroups/{0}/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{1}')&api-version={2}" -f "$TenantId".Trim(), "$EngineObjectId".Trim(), $script:PimEaaApi)) }
    catch { return $null }
}

function Get-PimEngineAzureAccessReport {
    <#
      READ-ONLY (the in-container updater, every update -- it may not grant roles). Reads, plans, and returns ONE line;
      never calls the seam with anything but GET, never throws.
      Returns @{ action = noop | report | unknown; line; plan; fix }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [object[]]$AssignmentRows = @(), [object[]]$DefinitionRows = @(),
          [string]$EngineObjectId = '', [string]$TenantId = '', [string]$Name = 'the engine', [switch]$IncludeRootUserAccessAdministrator)
    try {
        $def = Get-PimEngineAzureDefinedScopes -AssignmentRows $AssignmentRows -DefinitionRows $DefinitionRows
        if (-not @($def.scopes).Count) { return [pscustomobject]@{ action = 'noop'; line = "engine Azure access ($Name) -- no Azure scope is defined, nothing needed"; plan = $null; fix = '' } }
        if (-not "$EngineObjectId".Trim()) { return [pscustomobject]@{ action = 'unknown'; line = "engine Azure access ($Name) -- not checked (the engine identity could not be read)"; plan = $null; fix = '' } }
        $rd = Read-PimEngineAzureHeld -Arm $Arm -Scopes $def.scopes -EngineObjectId $EngineObjectId
        $plan = Get-PimEngineAzureAccessPlan -Scopes $def.scopes -Held $rd.held -TenantId $TenantId -IncludeRootUserAccessAdministrator:$IncludeRootUserAccessAdministrator
        $want = @($plan.rows | Where-Object { $_.action -in 'add', 'opt-in', 'unknown' } | ForEach-Object { $_.scope })
        $fix = Get-PimEngineAzureAccessFixCommand -TenantId $TenantId -EngineObjectId $EngineObjectId -Scopes $want
        $adds = @($plan.rows | Where-Object { $_.action -in 'add', 'opt-in' })
        $unk = @($plan.rows | Where-Object { $_.action -eq 'unknown' })
        if (-not $adds.Count -and -not $unk.Count) { return [pscustomobject]@{ action = 'noop'; line = "engine Azure access ($Name) -- $($plan.summary)"; plan = $plan; fix = '' } }
        $what = @()
        if ($adds.Count) { $what += ("MISSING User Access Administrator at " + (@($adds | ForEach-Object { $_.scope }) -join ', ')) }
        if ($unk.Count) { $what += ("not readable by the updater at " + (@($unk | ForEach-Object { $_.scope }) -join ', ')) }
        $act = if ($adds.Count) { 'report' } else { 'unknown' }
        return [pscustomobject]@{ action = $act; line = "engine Azure access ($Name) -- $($what -join '; '). The updater may not grant roles; an Owner / User Access Administrator of those scopes runs Confirm-PimInstall.ps1, or:`n$fix"; plan = $plan; fix = $fix }
    } catch {
        return [pscustomobject]@{ action = 'unknown'; line = "engine Azure access ($Name) -- not checked: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())"; plan = $null; fix = '' }
    }
}

function New-PimEngineAzureAssignmentRequest {
    <#
      PURE. The PUT this step sends for one scope: {scope}/providers/Microsoft.Authorization/roleAssignments/{new guid},
      User Access Administrator (guarded), principalType ServicePrincipal, the description marker (so a later run can
      tell its own grants from a person's). Below a subscription the role id is the subscription's; above it (a
      management group) the tenant-level id.
    #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$EngineObjectId, [string]$RoleGuid = $script:PimEaaUaaGuid, [string]$Name = '')
    Assert-PimEngineAzureGrantRole -RoleGuid $RoleGuid
    $sc = "$Scope".Trim().TrimEnd('/')
    $rd = if ($sc -match '^(?i)/subscriptions/([0-9a-fA-F-]{36})') { "/subscriptions/$($Matches[1])/providers/Microsoft.Authorization/roleDefinitions/$RoleGuid" } else { "/providers/Microsoft.Authorization/roleDefinitions/$RoleGuid" }
    $n = if ("$Name".Trim()) { "$Name".Trim() } else { [guid]::NewGuid().ToString() }
    [pscustomobject]@{
        Method = 'PUT'
        Path   = "$sc/providers/Microsoft.Authorization/roleAssignments/$n`?api-version=$($script:PimEaaApi)"
        Body   = @{ properties = @{ roleDefinitionId = $rd; principalId = "$EngineObjectId".Trim(); principalType = 'ServicePrincipal'; description = $script:PimEaaMarker } }
    }
}

function Invoke-PimEngineAzureAccessConverge {
    <#
      The APPLY, for setup scripts run by a PERSON (Confirm-PimInstall's repair). Reads, plans, and -- with -Apply --
      PUTs User Access Administrator at each 'add' scope, then READS IT BACK. -Apply:$false (-WhatIf / -NoRepair) = plan
      only ('would grant'). A refused PUT (the person lacks Owner / User Access Administrator there) is a WARNING with the
      exact command for the right person -- never a stop, never a throw. Never a DELETE.
      -Arm { param($method, $path, $body) }. -ReadBackAttempts / -ReadBackDelaySeconds: ARM may list a new assignment a
      few seconds late.
      Returns @{ ok; needed; plan; rows = @(@{ scope; state = covered | granted | would grant | refused | opt-in | unknown;
                 detail }); refused[]; fix; summary; notNeeded[] }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [object[]]$AssignmentRows = @(), [object[]]$DefinitionRows = @(),
          [Parameter(Mandatory)][string]$EngineObjectId, [string]$TenantId = '', [string]$Name = 'the engine',
          [bool]$Apply = $false, [switch]$IncludeRootUserAccessAdministrator, [int]$ReadBackAttempts = 3, [int]$ReadBackDelaySeconds = 5)
    # NOTE: plain locals, one result object built at the end. Windows PowerShell 5.1 threw "Argument types do not match" when
    # an EMPTY pipeline result was member-assigned into an [ordered] dictionary ($res.refused = @(... nothing ...)) -- so a
    # fully converged run (nothing refused) reported ok=$false "not converged" (test VM, 2026-10-29).
    $okV = $true; $neededV = $false; $planV = $null; $fixV = ''; $summaryV = ''
    $rowsV = New-Object System.Collections.Generic.List[object]
    $refusedV = New-Object System.Collections.Generic.List[string]
    $notNeededV = New-Object System.Collections.Generic.List[object]
    try {
        $def = Get-PimEngineAzureDefinedScopes -AssignmentRows $AssignmentRows -DefinitionRows $DefinitionRows
        if (-not @($def.scopes).Count) { $summaryV = 'no Azure scope is defined -- nothing needed' }
        else {
        $rd = Read-PimEngineAzureHeld -Arm $Arm -Scopes $def.scopes -EngineObjectId $EngineObjectId
        $all = Read-PimEngineAzureAllAssignments -Arm $Arm -TenantId $TenantId -EngineObjectId $EngineObjectId
        $plan = Get-PimEngineAzureAccessPlan -Scopes $def.scopes -Held $rd.held -AllAssignments $all -TenantId $TenantId -IncludeRootUserAccessAdministrator:$IncludeRootUserAccessAdministrator
        $planV = $plan; $neededV = [bool]$plan.needed
        foreach ($nn in @($plan.notNeeded)) { if ($null -ne $nn) { $notNeededV.Add($nn) } }
        $rows = $rowsV
        $grantedAny = $false
        # re-plan ONE scope from a fresh read (after a grant in this run: a management group granted first may now cover a
        # subscription under it -- ARM lists it as inherited -- so no second grant is made)
        $replan = {
            param($row)
            $again = Read-PimEngineAzureHeld -Arm $Arm -Scopes @($row.scope) -EngineObjectId $EngineObjectId
            $one = Get-PimEngineAzureAccessPlan -Scopes @([pscustomobject]@{ scope = $row.scope; sources = $row.sources }) -Held $again.held -TenantId $TenantId -IncludeRootUserAccessAdministrator:$IncludeRootUserAccessAdministrator
            return @($one.rows)[0]
        }
        foreach ($p in @($plan.rows)) {
            if ($p.action -eq 'add' -and $Apply -and $grantedAny) {
                $fresh = & $replan $p
                if ($fresh -and $fresh.action -eq 'covered') { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'covered'; detail = "$($fresh.reason) (a grant made in this run)" }); continue }
            }
            switch ($p.action) {
                'covered' { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'covered'; detail = $p.reason }) }
                'opt-in'  { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'opt-in'; detail = $p.reason }) }
                'unknown' { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'unknown'; detail = "$($p.reason)$(if ($rd.errors[$p.scope]) { ": $($rd.errors[$p.scope])" })" }) }
                'add' {
                    if (-not $Apply) { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'would grant'; detail = 'plan only (-WhatIf / -NoRepair)' }); continue }
                    $req = New-PimEngineAzureAssignmentRequest -Scope $p.scope -EngineObjectId $EngineObjectId
                    $err = ''
                    try { [void](& $Arm $req.Method $req.Path $req.Body) }
                    catch { $m = "$($_.Exception.Message)"; if ($m -notmatch '(?i)RoleAssignmentExists|already exists') { $err = (($m -split "`n")[0]).Trim() } }
                    # READ BACK: covered at the scope now? (never trust the PUT's answer)
                    $now = $false
                    for ($i = 0; $i -lt [Math]::Max(1, $ReadBackAttempts) -and -not $now; $i++) {
                        if ($i -gt 0 -and $ReadBackDelaySeconds -gt 0) { Start-Sleep -Seconds $ReadBackDelaySeconds }
                        $p2 = & $replan $p
                        $now = [bool]($p2 -and $p2.action -eq 'covered')
                    }
                    if ($now) { $grantedAny = $true; $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'granted'; detail = 'User Access Administrator granted and read back' }) }
                    else { $rows.Add([pscustomobject]@{ scope = $p.scope; state = 'refused'; detail = $(if ($err) { $err } else { 'not listed after the grant (read back failed)' }) }) }
                }
            }
        }
        $cnt = @{ 'covered' = 0; 'granted' = 0; 'would grant' = 0; 'refused' = 0; 'opt-in' = 0; 'unknown' = 0 }
        foreach ($r in $rowsV) {
            $st = "$($r.state)"
            if ($cnt.ContainsKey($st)) { $cnt[$st] = [int]$cnt[$st] + 1 }
            if ($st -eq 'refused' -or $st -eq 'opt-in' -or $st -eq 'unknown') { $refusedV.Add("$($r.scope)") }
        }
        if ($refusedV.Count -gt 0) { $okV = $false; $fixV = Get-PimEngineAzureAccessFixCommand -TenantId $TenantId -EngineObjectId $EngineObjectId -Scopes $refusedV.ToArray() }
        $summaryV = "$($rowsV.Count) defined Azure scope(s): $($cnt['covered']) covered, $($cnt['granted']) granted, $($cnt['would grant']) would grant, $($cnt['refused']) refused, $($cnt['opt-in']) opt-in, $($cnt['unknown']) not readable"
        }
    } catch {
        $okV = $false; $summaryV = "not converged: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())"
    }
    return [pscustomobject]@{ ok = $okV; needed = $neededV; plan = $planV; rows = $rowsV.ToArray(); refused = $refusedV.ToArray()
                              fix = $fixV; summary = $summaryV; notNeeded = $notNeededV.ToArray() }
}
