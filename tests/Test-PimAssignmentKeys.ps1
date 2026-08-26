#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-11 + BUG-17 -- the assignment scopes must key desired and live ALIKE, and must
    read their live set from the TENANT, not from their own desired rows.

    Two defects that masked each other:

      BUG-11  RolesAUs / GroupMembers / AzRes emitted a resolved key for a live row and a
              `tag:`/`src:` placeholder for a desired row, so NO live key could ever be a
              desired key. Consequences: the scope never converged (every run re-planned
              creates that already existed), and under -Prune every live row -- including
              rows the same pass had just created -- was classed as a removal.

      BUG-17  All five assignment scopes built their LIVE set out of the tags found in
              their own DESIRED rows. Delete a desired row and its live counterpart stops
              being read, so the prune that removal is supposed to trigger silently does
              nothing and the orphan stays in the tenant forever.

    Together: prune planned to delete what had to stay and could not see what had to go.

    The assertions below are the two that keep it fixed:
      1. a resolved desired row and its live counterpart produce the SAME key
      2. with an EMPTY desired set, a solution-owned group's live assignment is STILL in
         the live set (i.e. live is not derived from desired)
    Plus the scope split: PIM-for-Groups membership serves both AdminMembers (users) and
    GroupMembers (nested groups) from one endpoint, so each must take only its own rows or
    they would classify each other's as removals.

    Offline. No tenant, no network -- every live read is stubbed.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-EngineCore.ps1')          # Compare-PimDesiredVsLive -- the real diff, not a re-implementation
. (Join-Path $shared 'PIM-EngineProviders.ps1')

Write-Host "=== BUG-11/BUG-17: assignment keys agree, and live is not derived from desired ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# The synthetic estate. TWO groups, so "solution-owned" is a real set and not a
# tautology, and one AU. Ids are deliberately GUID-shaped: the whole point of the
# fix is that a desired row resolves to the SAME id the live row carries.
# ---------------------------------------------------------------------------
$GID_ROLEGRP = '11111111-1111-1111-1111-111111111111'   # PIM-TEST-ROLE-Operator      (tag ROLE-OPS)
$GID_PERMGRP = '22222222-2222-2222-2222-222222222222'   # PIM-TEST-Entra-UserAdmin    (tag PERM-UA)
$AU_ID      = '33333333-3333-3333-3333-333333333333'   # AU-TEST
$ADMIN_USER_ID      = '44444444-4444-4444-4444-444444444444'   # an admin USER (not a group)
$ARM_ROLE_GUID      = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'   # an ARM role definition guid

$script:Desired = @{}          # entity -> rows
$script:GroupMembership = @{}  # gid -> rows
$script:DirSchedules = @{}     # gid -> rows

function Get-PimDesiredRows { param([string]$Entity) if ($script:Desired.ContainsKey($Entity)) { return @($script:Desired[$Entity]) } return @() }
function Ensure-PimContextLoaded { }
function Resolve-PimLiveGroupIdByName {
    param([string]$Name)
    switch ("$Name") { 'PIM-TEST-ROLE-Operator' { return $GID_ROLEGRP } 'PIM-TEST-Entra-UserAdmin' { return $GID_PERMGRP } }
    return $null
}
function Get-PimLiveGroupMembership { param([string]$GroupId, [string]$GroupTag)
    if (-not $script:GroupMembership.ContainsKey($GroupId)) { return @() }
    @($script:GroupMembership[$GroupId] | ForEach-Object { [pscustomobject]@{ principalId=$_.principalId; accessId='member'; GroupTag=$GroupTag; AssignmentType=$_.AssignmentType } })
}
function Get-PimLiveDirRoleSchedules { param([string]$PrincipalId)
    if ($script:DirSchedules.ContainsKey($PrincipalId)) { return @($script:DirSchedules[$PrincipalId]) }
    @()
}
function Resolve-PimPrincipalId { param([string]$Upn) if ("$Upn" -eq 'admin-test@contoso.example') { return $ADMIN_USER_ID } return $null }
function Resolve-PimArmRoleId { param([string]$Scope, [string]$RoleName, [hashtable]$Cache) if ("$RoleName" -eq 'Reader') { return $ARM_ROLE_GUID } return $null }
$Global:Roles_All_ID = @([pscustomobject]@{ Id='role-ua'; DisplayName='User Administrator' }, [pscustomobject]@{ Id='role-hd'; DisplayName='Helpdesk Administrator' })
$Global:AU_All_ID    = @([pscustomobject]@{ Id=$AU_ID; DisplayName='AU-TEST' })

function Reset-Estate {
    $script:PimSolutionGroupsAt = $null       # the fix's per-run cache
    $script:Desired = @{
        'PIM-Definitions-Roles'    = @([pscustomobject]@{ GroupName='PIM-TEST-ROLE-Operator';   GroupTag='ROLE-OPS' })
        'PIM-Definitions-Services' = @([pscustomobject]@{ GroupName='PIM-TEST-Entra-UserAdmin'; GroupTag='PERM-UA' })
        'PIM-Definitions-AU'       = @([pscustomobject]@{ AdministrativeUnitTag='AU-T'; AUDisplayName='AU-TEST' })
    }
    $script:GroupMembership = @{}
    $script:DirSchedules = @{}
}

# ---------------------------------------------------------------------------
Write-Host "`n[the solution-owned group set]" -ForegroundColor Cyan
Reset-Estate
$owned = Get-PimSolutionOwnedGroups -Force
Assert "resolves both defined groups to live ids"        (@($owned.byId.Keys).Count -eq 2 -and $owned.byId.ContainsKey($GID_ROLEGRP) -and $owned.byId.ContainsKey($GID_PERMGRP))
Assert "indexes them by tag"                             ($owned.byTag['role-ops'] -eq $GID_ROLEGRP -and $owned.byTag['perm-ua'] -eq $GID_PERMGRP)
Assert "a group with no live id is NOT owned"            (-not $owned.byId.ContainsKey('99999999-9999-9999-9999-999999999999'))
# The set must come from the DEFINITIONS, so it does not shrink when assignment rows go.
$script:Desired['PIM-Assignments-Roles-AUs'] = @()
$script:PimSolutionGroupsAt = $null
Assert "the owned set does NOT depend on assignment rows" (@((Get-PimSolutionOwnedGroups -Force).byId.Keys).Count -eq 2)

# ---------------------------------------------------------------------------
Write-Host "`n[RolesAUs -- AU-scoped directory role]" -ForegroundColor Cyan
Reset-Estate
$script:Desired['PIM-Assignments-Roles-AUs'] = @([pscustomobject]@{
    GroupTag='PERM-UA'; AdministrativeUnitTag='AU-T'; RoleDefinitionName='Helpdesk Administrator'; AssignmentType='Eligible' })
$script:DirSchedules[$GID_PERMGRP] = @([pscustomobject]@{
    principalId=$GID_PERMGRP; RoleDefinitionName='Helpdesk Administrator'; AssignmentType='Eligible'
    roleDefinitionId='role-hd'; directoryScopeId="/administrativeUnits/$AU_ID" })
$p = New-PimRolesAUsProvider
$ctx = @{}
$des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "desired row resolves to the live group id"    ("$($des[0].principalId)" -eq $GID_PERMGRP)
Assert "desired row resolves the AU tag to a scope"   ("$($des[0].directoryScopeId)" -eq "/administrativeUnits/$AU_ID")
$kd = & $p.KeyOf $des[0]; $kl = & $p.KeyOf $liv[0]
Assert "KEYS AGREE (BUG-11)"                          ($kd -eq $kl -and $kd -notmatch '^unresolved:')
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "complete desired set -> nochange, no create"  ($diff.nochange.Count -eq 1 -and $diff.create.Count -eq 0)
Assert "complete desired set -> NOTHING pruned"       ($diff.remove.Count -eq 0)
# BUG-17: drop the desired row; the live assignment must STILL be seen, and now be a removal.
$script:Desired['PIM-Assignments-Roles-AUs'] = @()
$script:PimSolutionGroupsAt = $null
$ctx = @{}; $des2 = @(& $p.GetDesired $ctx); $liv2 = @(& $p.GetLive $ctx)
Assert "empty desired -> live is STILL read (BUG-17)" ($liv2.Count -eq 1)
$diff2 = Compare-PimDesiredVsLive -Desired $des2 -Live $liv2 -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "  ...and the orphan is a REMOVAL"             ($diff2.remove.Count -eq 1)
# an unresolved desired row can never collide with a live key
$script:Desired['PIM-Assignments-Roles-AUs'] = @([pscustomobject]@{
    GroupTag='NOSUCH'; AdministrativeUnitTag='AU-T'; RoleDefinitionName='Helpdesk Administrator'; AssignmentType='Eligible' })
$script:PimSolutionGroupsAt = $null
$ctx = @{}; $des3 = @(& $p.GetDesired $ctx)
Assert "unresolved desired row keys as 'unresolved:'" ((& $p.KeyOf $des3[0]) -match '^unresolved:')

# ---------------------------------------------------------------------------
Write-Host "`n[GroupMembers -- nested PIM group]" -ForegroundColor Cyan
Reset-Estate
# 🔴 THE TARGET/SOURCE LABELS HERE WERE SWAPPED RELATIVE TO THE REAL AUTHORED DATA, and because the
# provider was written to match this fixture, code and test agreed with each other while both
# disagreed with the customer's tenant. Corrected 2026-08-10 from live evidence:
#   * the authored rows are Target=<ROLE group>, Source=<service/permission group>;
#   * the live tenant nests the ROLE group INSIDE the service group
#     (PIM-ROLE-Management-IT-OperationSecurity is a MEMBER OF 50 Entra-ID-* groups, and contains 1);
#   * with the old direction 0 of 206 desired rows matched live; with this one, 196 match.
# So: SOURCE supplies the permission and is the CONTAINER, TARGET receives it and is the MEMBER.
$script:Desired['PIM-Assignments-Groups'] = @([pscustomobject]@{
    TargetGroupTag='ROLE-OPS'; SourceGroupTag='PERM-UA'; AssignmentType='Eligible' })
# the CONTAINER (the source/permission group) holds BOTH the nested role group AND an admin user --
# one endpoint, two scopes
$script:GroupMembership[$GID_PERMGRP] = @(
    [pscustomobject]@{ principalId=$GID_ROLEGRP; AssignmentType='Eligible' }
    [pscustomobject]@{ principalId=$ADMIN_USER_ID;      AssignmentType='Eligible' })
$p = New-PimGroupMembersProvider
$ctx = @{}; $des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "desired row resolves the TARGET group id (the MEMBER)" ("$($des[0].principalId)" -eq $GID_ROLEGRP)
Assert "live keeps ONLY the nested-group row"         ($liv.Count -eq 1 -and "$($liv[0].principalId)" -eq $GID_ROLEGRP)
Assert "KEYS AGREE (BUG-11)"                          ((& $p.KeyOf $des[0]) -eq (& $p.KeyOf $liv[0]))
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "complete desired set -> nochange, nothing pruned" ($diff.nochange.Count -eq 1 -and $diff.create.Count -eq 0 -and $diff.remove.Count -eq 0)
$script:Desired['PIM-Assignments-Groups'] = @()
$script:PimSolutionGroupsAt = $null
$ctx = @{}; $liv2 = @(& $p.GetLive $ctx)
Assert "empty desired -> live is STILL read (BUG-17)" ($liv2.Count -eq 1)

# ---------------------------------------------------------------------------
Write-Host "`n[AdminMembers -- the complementary half of the same endpoint]" -ForegroundColor Cyan
Reset-Estate
$script:Desired['PIM-Assignments-Admins'] = @([pscustomobject]@{
    Username='admin-test@contoso.example'; GroupTag='PERM-UA'; AssignmentType='Eligible' })
$script:GroupMembership[$GID_PERMGRP] = @(
    [pscustomobject]@{ principalId=$GID_ROLEGRP; AssignmentType='Eligible' }
    [pscustomobject]@{ principalId=$ADMIN_USER_ID;      AssignmentType='Eligible' })
$p = New-PimAdminMembersProvider
$ctx = @{}; $des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "live keeps ONLY the USER row (not the nested group)" ($liv.Count -eq 1 -and "$($liv[0].principalId)" -eq $ADMIN_USER_ID)
Assert "KEYS AGREE"                                   ((& $p.KeyOf $des[0]) -eq (& $p.KeyOf $liv[0]))
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "complete desired set -> nothing pruned"       ($diff.remove.Count -eq 0 -and $diff.create.Count -eq 0)
Assert "the two scopes PARTITION the membership"      (($liv.Count + 1) -eq @($script:GroupMembership[$GID_PERMGRP]).Count)

# ---------------------------------------------------------------------------
Write-Host "`n[EntraRoles -- tenant-scoped directory role]" -ForegroundColor Cyan
Reset-Estate
$script:Desired['PIM-Assignments-Roles-Groups'] = @([pscustomobject]@{
    GroupTag='PERM-UA'; RoleDefinitionName='User Administrator'; AssignmentType='Eligible' })
$script:DirSchedules[$GID_PERMGRP] = @([pscustomobject]@{
    principalId=$GID_PERMGRP; RoleDefinitionName='User Administrator'; AssignmentType='Eligible'
    roleDefinitionId='role-ua'; directoryScopeId='/' })
$p = New-PimEntraRolesProvider
$ctx = @{}; $des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "KEYS AGREE"                                   ((& $p.KeyOf $des[0]) -eq (& $p.KeyOf $liv[0]))
# THE BUG-17 case that D2 measured live: delete the desired row, the orphan must appear.
$script:Desired['PIM-Assignments-Roles-Groups'] = @()
$script:PimSolutionGroupsAt = $null
$ctx = @{}; $des2 = @(& $p.GetDesired $ctx); $liv2 = @(& $p.GetLive $ctx)
Assert "empty desired -> the orphan is STILL live (BUG-17)" ($liv2.Count -eq 1)
$diff = Compare-PimDesiredVsLive -Desired $des2 -Live $liv2 -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "  ...and prune classes it as a removal"       ($diff.remove.Count -eq 1)
Assert "AU-scoped rows are NOT in EntraRoles"         (@(& $p.GetLive @{} | Where-Object { "$($_.directoryScopeId)" -match 'administrativeUnits' }).Count -eq 0)

# ---------------------------------------------------------------------------
Write-Host "`n[AzRes -- Azure RBAC at an ARM scope]" -ForegroundColor Cyan
Reset-Estate
$AZ_SCOPE = '/subscriptions/00000000-0000-0000-0000-000000000000'
$script:Desired['PIM-Assignments-Azure-Resources'] = @([pscustomobject]@{
    GroupTag='PERM-UA'; AzScope=$AZ_SCOPE; AzScopePermission='Reader'; AssignmentType='Eligible' })
$script:ArmRows = @(
    [pscustomobject]@{ properties = [pscustomobject]@{ principalId=$GID_PERMGRP; scope=$AZ_SCOPE; roleDefinitionId="$AZ_SCOPE/providers/Microsoft.Authorization/roleDefinitions/$ARM_ROLE_GUID" } }
    [pscustomobject]@{ properties = [pscustomobject]@{ principalId='55555555-5555-5555-5555-555555555555'; scope=$AZ_SCOPE; roleDefinitionId="$AZ_SCOPE/providers/Microsoft.Authorization/roleDefinitions/$ARM_ROLE_GUID" } }  # NOT ours
    [pscustomobject]@{ properties = [pscustomobject]@{ principalId=$GID_PERMGRP; scope='/subscriptions/other'; roleDefinitionId="$AZ_SCOPE/providers/Microsoft.Authorization/roleDefinitions/$ARM_ROLE_GUID" } }              # inherited
)
function Invoke-PimArm { param([string]$Method='GET', [string]$Path, [string]$ApiVersion, [object]$Body, [switch]$All)
    if ($Path -match 'roleEligibilityScheduleInstances') { return @($script:ArmRows) }
    return @()
}
$p = New-PimAzResProvider
$ctx = @{}; $des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "desired resolves group id AND the ARM role guid" ("$($des[0].principalId)" -eq $GID_PERMGRP -and "$($des[0].RoleId)" -eq $ARM_ROLE_GUID)
Assert "live keeps only OUR principal, at THIS scope"    ($liv.Count -eq 1 -and "$($liv[0].principalId)" -eq $GID_PERMGRP -and "$($liv[0].AzScope)" -eq $AZ_SCOPE)
Assert "KEYS AGREE (BUG-11)"                             ((& $p.KeyOf $des[0]) -eq (& $p.KeyOf $liv[0]))
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "complete desired set -> nothing pruned"          ($diff.remove.Count -eq 0 -and $diff.create.Count -eq 0)
$script:Desired['PIM-Assignments-Azure-Resources'] = @()
$script:Desired['PIM-Definitions-Resources'] = @([pscustomobject]@{ AzScope = $AZ_SCOPE })
$script:PimSolutionGroupsAt = $null
$ctx = @{}; $liv2 = @(& $p.GetLive $ctx)
Assert "scope universe comes from the RESOURCE definitions (BUG-17)" ($liv2.Count -eq 1)

# ---------------------------------------------------------------------------
# The regression that would undo all of this: a provider going back to "live from
# desired". Assert it structurally, by NAME, so a future edit is caught in review.
Write-Host "`n[structural: no assignment provider may derive live from its own desired rows]" -ForegroundColor Cyan
$src = Get-Content -LiteralPath (Join-Path $shared 'PIM-EngineProviders.ps1') -Raw
foreach ($fn in 'New-PimRolesAUsProvider','New-PimGroupMembersProvider','New-PimAdminMembersProvider','New-PimEntraRolesProvider','New-PimAzResProvider') {
    $i = $src.IndexOf("function $fn")
    $body = if ($i -ge 0) { $src.Substring($i, [Math]::Min(6000, $src.Length - $i)) } else { '' }
    $g = $body.IndexOf('GetLive')
    $getLive = if ($g -ge 0) { $body.Substring($g, [Math]::Min(2600, $body.Length - $g)) } else { '' }
    Assert "$fn GetLive calls Get-PimSolutionOwnedGroups" ($getLive -match 'Get-PimSolutionOwnedGroups')
}

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
