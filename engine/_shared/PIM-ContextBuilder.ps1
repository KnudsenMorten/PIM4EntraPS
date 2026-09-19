#Requires -Version 5.1
<#
.SYNOPSIS
    Generic Entra context builder + filtered-list accessor for PIM4EntraPS
    engines. Replaces the inline Get-MgUser/Get-MgGroup + Where-Object blocks
    that were duplicated across (and within) engine scripts.

.DESCRIPTION
    Two functions:

      Build-PimContext [-Refresh] [-CacheSeconds 300]
        Fetches raw Entra lists (users, groups, AUs, roles) ONCE, then applies
        every scriptblock in $global:PIM_Filters to produce filtered globals
        with the same names the legacy engines used:

          $Global:Users_All_ID                          (raw)
          $Global:Groups_All_ID                         (raw)
          $Global:AU_All_ID                             (raw)
          $Global:Roles_All_ID                          (raw)
          $Global:Accounts_Definitions_ID               (Admins filter; legacy alias: AdminCandidate)
          $Global:PIM_Groups_Definitions_ID             (PimGroup filter)
          $Global:PIM_Groups_Resource_SyncAD_Definitions_ID  (PimGroupResourceSyncAD)
          $Global:PIM_Groups_Service_SyncAD_Definitions_ID   (PimGroupServiceSyncAD)
          $Global:Role_AU_Definitions_ID                (AURoleAllowed filter)

        Backward-compatible: engines that reference the legacy variable names
        keep working unchanged. Engines that adopt Get-PimList get a cleaner API.

        Cached for $CacheSeconds (default 300s = 5 min). Re-call with -Refresh
        to force a fresh Graph fetch; otherwise repeat calls within the cache
        window are no-ops.

      Get-PimList -Kind <name>
        Convenience accessor. Triggers Build-PimContext if context isn't yet
        built. Returns the global filtered list for the given kind.

        Valid kinds: Users, Groups, AUs, Roles, Admins, PimGroups,
        PimGroupsResourceSyncAD, PimGroupsServiceSyncAD, AURoles

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP

    Prereqs (caller's responsibility):
      - $global:PIM_Filters must be loaded (Initialize-LauncherConfig does this).
      - Microsoft Graph PowerShell SDK must be imported + authenticated.
#>

function Get-PimContextExtraGroupNames {
    # IMP-49 i (ss33.28). The group names the DEFINITIONS manage that do NOT start with the lean-fetch prefix
    # (e.g. DEPT-/PROJ- groups, or a non-'PIM-' naming convention). Unique, case-insensitive. Empty when the
    # definition reader is not loaded (a bare context build) -- the on-demand by-name lookup still covers them.
    param([string]$Prefix = 'PIM')
    $rows = @()
    try {
        if (Get-Command Get-PimGroupPolicyDefinitionRows -ErrorAction SilentlyContinue) { $rows = @(Get-PimGroupPolicyDefinitionRows) }
        elseif (Get-Command Get-PimGroupDefinitionRows -ErrorAction SilentlyContinue) { $rows = @(Get-PimGroupDefinitionRows) }
    } catch { Write-Verbose "Get-PimContextExtraGroupNames: definitions unreadable: $($_.Exception.Message)"; return @() }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $n = ''
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains('GroupName')) { $n = "$($r['GroupName'])".Trim() } }
        elseif ($r.PSObject.Properties['GroupName']) { $n = "$($r.GroupName)".Trim() }
        if (-not $n -or $n.StartsWith("$Prefix", [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        $k = $n.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true; $out.Add($n)
    }
    return $out.ToArray()
}

function Build-PimContext {
    [CmdletBinding()]
    param(
        [switch]$Refresh,
        [int]$CacheSeconds = 300
    )

    if (-not $Refresh -and $Global:PimContextBuiltAt -and `
        ((Get-Date) - $Global:PimContextBuiltAt).TotalSeconds -lt $CacheSeconds) {
        Write-Verbose ("Build-PimContext: cache hit (built {0:N0}s ago, window {1}s)" -f `
            ((Get-Date) - $Global:PimContextBuiltAt).TotalSeconds, $CacheSeconds)
        return
    }

    # The RAW lists (groups, AUs, role catalog) do not depend on the filters -- only the derived
    # *_Definitions_ID globals do, and those are read by the v1 module only; no v2 engine code uses
    # them. Throwing here took the role catalog down with the filters, so the v2 scheduler (which
    # loads no filters file -- v2 is SQL-only) got "unresolved role" on every Entra role assignment.
    # No filters is therefore the NORMAL v2 case: load the raw lists, skip the v1 filtered views.
    $__noFilters = -not $global:PIM_Filters
    if ($__noFilters) {
        Write-Verbose 'Build-PimContext: no $global:PIM_Filters (v2) -- raw groups/AUs/roles load; the v1 filtered lists are skipped.'
    }

    # Backend: PURE REST by default (no Graph module -> nothing to Install-Module,
    # no version drift, no auto-import demanding Connect-MgGraph) so the engine runs
    # identically on a VM or container. Set $global:PIM_UseGraphSdk = $true to opt
    # back into the legacy Graph SDK path. REST results are normalized to SDK
    # property casing so the filters below ($user.UserPrincipalName,
    # $group.DisplayName, ...) work either way.
    $useSdk = [bool]$global:PIM_UseGraphSdk
    if ($useSdk) {
        Write-Host '[context] Fetching Entra users + groups + AUs + roles from Graph (SDK)...'
        $Global:Users_All_ID  = Get-MgUser -All
        $Global:Groups_All_ID = Get-MgGroup -All
        $Global:AU_All_ID     = Get-MgDirectoryAdministrativeUnit -All
        $Global:Roles_All_ID  = Get-MgRoleManagementDirectoryRoleDefinition
    }
    else {
        if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
            $rest = Join-Path (Split-Path -Parent $PSCommandPath) 'PIM-Rest.ps1'
            if (Test-Path $rest) { . $rest } else { throw 'Build-PimContext: no Graph SDK and PIM-Rest.ps1 not found.' }
        }
        # LEAN context (default for the engine): a real tenant can have 150k+ groups and
        # 500k+ users -- bulk-listing them to manage a few hundred PIM groups + admins is
        # unworkable. So: USERS are never bulk-listed (resolved on-demand + cached by
        # Resolve-PimPrincipalId); GROUPS are fetched with a SERVER-SIDE $filter on the PIM
        # name prefix (not the whole directory); AUs + role definitions are bounded so they
        # stay bulk. Set $global:PIM_LeanContext=$false to force the old full-list behaviour.
        $lean = ($null -eq $global:PIM_LeanContext) -or [bool]$global:PIM_LeanContext
        # REQ-U (2.4.378, operator: "customer can have different naming convention so you must make sure code uses the actual
        # naming per tenant and not generic"): the prefix is the TENANT's (its PimGroupPattern's literal head), never a
        # generic 'PIM'. A pattern with no literal head selects nothing by prefix -- the definition-named groups below
        # (Get-PimContextExtraGroupNames) are then the whole managed set, which is exactly right for such a tenant.
        $prefix = if ("$($global:PIM_GroupNamePrefix)".Trim()) { "$($global:PIM_GroupNamePrefix)".Trim() }
                  elseif (Get-Command Get-PimGroupNamePrefix -ErrorAction SilentlyContinue) { "$(Get-PimGroupNamePrefix)".Trim() }
                  else { 'PIM' }
        if ($lean) {
            Write-Host "[context] LEAN fetch (REST): users on-demand; groups startswith '$prefix'; AUs + roles bulk..."
            $Global:Users_All_ID  = @()   # resolved on-demand (no 500k bulk list)
            $hdr = @{ ConsistencyLevel = 'eventual' }
            $Global:Groups_All_ID = if ($prefix) {
                @(Invoke-PimGraph -Headers $hdr -Path "/groups?`$filter=startswith(displayName,'$($prefix -replace "'", "''")')&`$select=id,displayName,groupTypes,securityEnabled,mailNickname,description&`$count=true&`$top=999" -All | ConvertTo-PimSdkShape)
            } else {
                Write-Host "[context] the tenant's group pattern has no literal prefix -- groups are resolved by the names the definitions give" -ForegroundColor DarkGray
                @()
            }
            # IMP-49 i (ss33.28) -- VERIFIED: the lean fetch holds ONLY '$prefix*' groups, but a managed group need not
            # carry that prefix (a naming convention that is not 'PIM-...', a department/project group named
            # 'DEPT-...' / 'PROJ-...', a group adopted by name). Such a group was missing from the live set, so the
            # Groups provider planned a CREATE for it on every run, and every by-name lookup paid a Graph round-trip.
            # The groups the DEFINITIONS name outside the prefix are now resolved here too -- by exact displayName,
            # 15 per request -- so the lean context holds every managed group and still never lists the directory.
            try {
                $extra = @(Get-PimContextExtraGroupNames -Prefix $prefix)
                if ($extra.Count) {
                    $have = @{}; foreach ($g in @($Global:Groups_All_ID)) { if ($g -and $g.Id) { $have["$($g.Id)"] = $true } }
                    $added = 0
                    for ($i = 0; $i -lt $extra.Count; $i += 15) {
                        $slice = @($extra[$i..([Math]::Min($i + 14, $extra.Count - 1))])
                        $in = (@($slice | ForEach-Object { "'" + ("$_" -replace "'", "''") + "'" }) -join ',')
                        foreach ($g in @(Invoke-PimGraph -Headers $hdr -Path "/groups?`$filter=displayName in ($in)&`$select=id,displayName,groupTypes,securityEnabled,mailNickname,description&`$count=true" -All | ConvertTo-PimSdkShape)) {
                            if ($g -and $g.Id -and -not $have.ContainsKey("$($g.Id)")) { $Global:Groups_All_ID += $g; $have["$($g.Id)"] = $true; $added++ }
                        }
                    }
                    Write-Host ("[context] + {0} managed group(s) outside the '{1}' prefix resolved by name ({2} named by the definitions)" -f $added, $prefix, $extra.Count)
                }
            } catch { Write-Warning "[context] groups named outside the '$prefix' prefix could not be resolved (they are resolved one by one on demand instead): $($_.Exception.Message)" }
        }
        else {
            Write-Host '[context] FULL fetch (REST): users + groups + AUs + roles...'
            $Global:Users_All_ID  = @(Invoke-PimGraph -Path "/users?`$select=id,userPrincipalName,displayName,mail,accountEnabled" -All | ConvertTo-PimSdkShape)
            $Global:Groups_All_ID = @(Invoke-PimGraph -Path "/groups?`$select=id,displayName,groupTypes,securityEnabled,mailNickname,description" -All | ConvertTo-PimSdkShape)
        }
        $Global:AU_All_ID     = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName,visibility" -All | ConvertTo-PimSdkShape)
        $Global:Roles_All_ID  = @(Invoke-PimGraph -Path "/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,templateId" -All | ConvertTo-PimSdkShape)
    }

    # Filter-key -> (sourceGlobalName, outputGlobalName).
    # Source is the global to filter from; output is where to assign the result.
    # Order matters: PimGroupResourceSyncAD/PimGroupServiceSyncAD filter the
    # already-filtered PimGroup result, not raw Groups_All_ID.
    $map = [ordered]@{
        Admins                   = @('Users_All_ID',                'Accounts_Definitions_ID')
        PimGroup                 = @('Groups_All_ID',               'PIM_Groups_Definitions_ID')
        PimGroupResourceSyncAD   = @('PIM_Groups_Definitions_ID',   'PIM_Groups_Resource_SyncAD_Definitions_ID')
        PimGroupServiceSyncAD    = @('PIM_Groups_Definitions_ID',   'PIM_Groups_Service_SyncAD_Definitions_ID')
        AURoleAllowed            = @('Roles_All_ID',                'Role_AU_Definitions_ID')
    }

    foreach ($key in $map.Keys) {
        # Resolve the filter scriptblock. 'Admins' is the canonical key; honour the
        # legacy 'AdminCandidate' key as a back-compat alias if a customer .custom.ps1
        # still sets it (and 'Admins' isn't set).
        if ($__noFilters) { continue }
        $filter = $global:PIM_Filters.$key
        if (-not $filter -and $key -eq 'Admins') { $filter = $global:PIM_Filters.AdminCandidate }
        if (-not $filter) {
            Write-Verbose ("Build-PimContext: filter '{0}' not defined in `$global:PIM_Filters -- skipping" -f $key)
            continue
        }
        $srcName, $dstName = $map[$key]
        $source = Get-Variable -Scope Global -Name $srcName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $source) {
            Write-Verbose ("Build-PimContext: source `$Global:{0} not set yet (skipping {1})" -f $srcName, $key)
            continue
        }
        $filtered = @($source | Where-Object { & $filter $_ })
        Set-Variable -Scope Global -Name $dstName -Value $filtered
        Write-Host ("[context] {0,-26} -> `${1}: {2} item(s)" -f $key, $dstName, $filtered.Count)
    }

    $Global:PimContextBuiltAt = Get-Date
}

function Merge-PimCacheItem {
    # PURE (no globals -> unit-testable): given the current cache array + a raw REST object,
    # return the NEW array with the object shaped (PascalCase aliases added so resolvers match
    # on .Id/.DisplayName) and appended, de-duped by id. Inline shaping (no ConvertTo-PimSdkShape
    # dependency, which can resolve to a different module's copy when PIM-Functions is loaded).
    param([object[]]$Current = @(), [Parameter(Mandatory)][object]$Object)
    $cur = @($Current)
    if (-not $Object) { return $cur }
    $o = [ordered]@{}
    foreach ($p in $Object.PSObject.Properties) {
        $o[$p.Name] = $p.Value
        if ($p.Name.Length -ge 1) { $pas = $p.Name.Substring(0, 1).ToUpperInvariant() + $p.Name.Substring(1); if (-not $o.Contains($pas)) { $o[$pas] = $p.Value } }
    }
    $shaped = [pscustomobject]$o
    $id = "$($shaped.Id)"; if (-not $id) { $id = "$($shaped.id)" }
    if ($id -and (@($cur) | Where-Object { "$($_.Id)" -eq $id -or "$($_.id)" -eq $id })) { return $cur }   # already cached
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in $cur) { $list.Add($c) }
    $list.Add($shaped)
    return $list.ToArray()   # NB: no leading-comma return -- a comma-wrapped value gets double-wrapped (nested array) when captured into Set-Variable -Value (...)
}

function Add-PimContextObject {
    # INCREMENTAL refresh: append a just-created object to the in-memory cache instead of
    # re-fetching the whole directory. Thin global wrapper around the pure Merge-PimCacheItem.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Group','User','AU','Role')][string]$Kind,
        [Parameter(Mandatory)][object]$Object
    )
    if (-not $Object) { return }
    $var = @{ Group = 'Groups_All_ID'; User = 'Users_All_ID'; AU = 'AU_All_ID'; Role = 'Roles_All_ID' }[$Kind]
    # FLATTEN on read: Get-Variable -ValueOnly wrapped in @() can nest the stored array, and a
    # prior run may already have nested it -- this loop self-heals to a flat object list.
    $raw = Get-Variable -Scope Global -Name $var -ValueOnly -ErrorAction SilentlyContinue
    $flat = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($raw)) { if ($c -is [System.Array]) { foreach ($x in $c) { $flat.Add($x) } } elseif ($null -ne $c) { $flat.Add($c) } }
    $merged = Merge-PimCacheItem -Current $flat.ToArray() -Object $Object
    Set-Variable -Scope Global -Name $var -Value ([object[]]$merged)   # cast => flat array, no @()-wrap nesting
    # §70.22 (live 2026-09-14 07:17Z): Groups created DEPT-testdept1, and AdminMembers in the SAME run failed "unresolved
    # principal/group" -- Get-PimSolutionOwnedGroups served its 5-minute cache from before the create. A new group
    # invalidates that cache (a global flag: the two files are dot-sourced into different script scopes).
    if ($Kind -eq 'Group') { $global:PIM_OwnedGroupsDirty = $true }
}

function Get-PimList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Users','Groups','AUs','Roles','Admins','PimGroups','PimGroupsResourceSyncAD','PimGroupsServiceSyncAD','AURoles')]
        [string]$Kind
    )

    $varMap = @{
        Users                   = 'Users_All_ID'
        Groups                  = 'Groups_All_ID'
        AUs                     = 'AU_All_ID'
        Roles                   = 'Roles_All_ID'
        Admins                  = 'Accounts_Definitions_ID'
        PimGroups               = 'PIM_Groups_Definitions_ID'
        PimGroupsResourceSyncAD = 'PIM_Groups_Resource_SyncAD_Definitions_ID'
        PimGroupsServiceSyncAD  = 'PIM_Groups_Service_SyncAD_Definitions_ID'
        AURoles                 = 'Role_AU_Definitions_ID'
    }

    if (-not $Global:PimContextBuiltAt) {
        Write-Verbose 'Get-PimList: context not built -- calling Build-PimContext first.'
        Build-PimContext
    }

    Get-Variable -Scope Global -Name $varMap[$Kind] -ValueOnly -ErrorAction Stop
}
