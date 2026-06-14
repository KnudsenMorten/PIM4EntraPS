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
          $Global:Accounts_Definitions_ID               (AdminCandidate filter)
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

    if (-not $global:PIM_Filters) {
        throw 'Build-PimContext: $global:PIM_Filters not loaded. Call Initialize-LauncherConfig first (which sources PIM4EntraPS.Filters.locked.ps1).'
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
        $prefix = if ("$($global:PIM_GroupNamePrefix)".Trim()) { "$($global:PIM_GroupNamePrefix)".Trim() } else { 'PIM' }
        if ($lean) {
            Write-Host "[context] LEAN fetch (REST): users on-demand; groups startswith '$prefix'; AUs + roles bulk..."
            $Global:Users_All_ID  = @()   # resolved on-demand (no 500k bulk list)
            $hdr = @{ ConsistencyLevel = 'eventual' }
            $Global:Groups_All_ID = @(Invoke-PimGraph -Headers $hdr -Path "/groups?`$filter=startswith(displayName,'$prefix')&`$select=id,displayName,groupTypes,securityEnabled,mailNickname,description&`$count=true&`$top=999" -All | ConvertTo-PimSdkShape)
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
        AdminCandidate           = @('Users_All_ID',                'Accounts_Definitions_ID')
        PimGroup                 = @('Groups_All_ID',               'PIM_Groups_Definitions_ID')
        PimGroupResourceSyncAD   = @('PIM_Groups_Definitions_ID',   'PIM_Groups_Resource_SyncAD_Definitions_ID')
        PimGroupServiceSyncAD    = @('PIM_Groups_Definitions_ID',   'PIM_Groups_Service_SyncAD_Definitions_ID')
        AURoleAllowed            = @('Roles_All_ID',                'Role_AU_Definitions_ID')
    }

    foreach ($key in $map.Keys) {
        if (-not $global:PIM_Filters.$key) {
            Write-Verbose ("Build-PimContext: filter '{0}' not defined in `$global:PIM_Filters -- skipping" -f $key)
            continue
        }
        $srcName, $dstName = $map[$key]
        $source = Get-Variable -Scope Global -Name $srcName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $source) {
            Write-Verbose ("Build-PimContext: source `$Global:{0} not set yet (skipping {1})" -f $srcName, $key)
            continue
        }
        $filter = $global:PIM_Filters.$key
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
