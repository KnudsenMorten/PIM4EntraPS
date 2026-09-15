#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-155 -- the Microsoft Graph application roles the DEPLOY identity needs, and the pure plan
    that decides which are still missing. Dot-sourced by New-PimDeployIdentity.ps1 -GrantGraph;
    offline-tested by tests/Test-PimDeployIdentityGraph.ps1.

.DESCRIPTION
    New-PimDeployIdentity.ps1 granted the deploy identity Owner on the subscription and NOTHING in
    Graph. The infra step then resolves each container's managed identity and grants it its own
    Graph roles (Resolve-PimMiAppId / Grant-PimMiGraph in _PimSetupShared.ps1), which needs the
    DEPLOYING identity to read the directory and write app-role assignments -- so a public user who
    followed the documented path stopped with "the DEPLOYING identity was REFUSED". The internal
    estate never hit it: its onboarding identity carries a directory admin role granted outside PIM.

    Only what the deploy itself calls is listed -- not the engine's set (that goes to the managed
    identities, never to the deploy identity):
      * Directory.Read.All              -- resolve managed identities / service principals
      * AppRoleAssignment.ReadWrite.All -- grant the managed identities their Graph app roles
      * Application.Read.All            -- read the target service principals while doing so
    The ids are the SAME values _PimSetupShared.ps1 grants; the test pins that they agree.
#>

function Get-PimDeployIdentityGraphRoles {
    [ordered]@{
        'Directory.Read.All'              = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
        'AppRoleAssignment.ReadWrite.All' = '06b708a9-e830-4db3-a914-8e69da51d44f'
        'Application.Read.All'            = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
    }
}

function Get-PimDeployIdentityGraphPlan {
    <#
      PURE. Given the appRoleIds the deploy identity already holds on Microsoft Graph, return the
      roles still to grant, as @{ Name; Id } objects in a stable order. Comparison is
      case-insensitive; unrelated roles the identity holds are ignored, never removed.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][string[]]$AssignedRoleIds)
    $have = @{}
    foreach ($r in @($AssignedRoleIds)) { if ("$r".Trim()) { $have["$r".Trim().ToLowerInvariant()] = $true } }
    $need = Get-PimDeployIdentityGraphRoles
    $out = @()
    foreach ($k in $need.Keys) {
        if (-not $have.ContainsKey($need[$k].ToLowerInvariant())) { $out += [pscustomobject]@{ Name = $k; Id = $need[$k] } }
    }
    return $out   # callers wrap in @(): an empty plan is $null -> @() count 0
}

function New-PimAppRoleAssignmentBody {
    <# PURE. The JSON body for POST /servicePrincipals/{id}/appRoleAssignments. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$ResourceId,
        [Parameter(Mandatory)][string]$AppRoleId
    )
    return (@{ principalId = $PrincipalId; resourceId = $ResourceId; appRoleId = $AppRoleId } | ConvertTo-Json -Compress)
}
