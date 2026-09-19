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
      * DelegatedPermissionGrant.ReadWrite.All -- consent the Manager's sign-in scopes (BUG-169)
    The ids are the SAME values _PimSetupShared.ps1 grants; the test pins that they agree.
#>

# 🔴 BUG-169 -- THE SCOPES A HUMAN SIGN-IN TO THE MANAGER ASKS FOR. Easy Auth on the v2 issuer requests
# openid/profile/email (offline_access when it keeps a refresh token), and the registration lists
# User.Read. ALL of them need consent; the setup used to consent User.Read alone, so in a tenant where
# users may not consent for themselves every sign-in stopped at "Need admin approval".
# Ids read from the live Microsoft Graph service principal 2026-09-18.
function Get-PimEasyAuthConsentScopes {
    [ordered]@{
        'openid'         = '37f7f235-527c-4136-accd-4a02d197296e'
        'profile'        = '14dad69e-099b-42c9-810b-d002981feec1'
        'email'          = '64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0'
        'offline_access' = '7427e0e9-2fba-42fe-b0c0-848c9e6a8182'
        'User.Read'      = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'
    }
}

function Get-PimEasyAuthConsentPlan {
    <#
      PURE. Given the scope string of the EXISTING tenant-wide (AllPrincipals) grant on Microsoft
      Graph -- or $null when there is none -- decide what to write:
        action 'none'   every required scope is already consented
        action 'create' no grant exists: POST one carrying all required scopes
        action 'patch'  a grant exists but lacks some: PATCH it to the UNION (never drop a scope
                        someone else consented -- a narrower grant could break another sign-in)
      Scope names compare case-insensitively (Entra treats them so); the result keeps the
      existing grant's spelling and order, then appends what is missing.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$ExistingScope, [switch]$GrantExists)
    $want = @((Get-PimEasyAuthConsentScopes).Keys)
    $have = @("$ExistingScope".Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
    $haveLc = @($have | ForEach-Object { $_.ToLowerInvariant() })
    $missing = @($want | Where-Object { $haveLc -notcontains $_.ToLowerInvariant() })
    $action = if (-not $missing.Count) { 'none' } elseif ($GrantExists) { 'patch' } else { 'create' }
    return [pscustomobject]@{ Action = $action; Missing = $missing; Scope = (@($have) + $missing) -join ' ' }
}

function Get-PimDeployIdentityGraphRoles {
    # 71.18 (Friday build audit, 2026-09-15): + Group.Create + GroupMember.ReadWrite.All. The prereq step converges the
    # SQL admin group (grp-pim-sql-admins: create it if absent, add the environment identities) AS the deploy identity;
    # without these two it only WARNED ("permission denied") and a fresh environment kept a single-identity SQL admin,
    # so the build could not run unattended. Least privilege on purpose: not Group.ReadWrite.All (that edits EVERY group).
    # Ids read from the live Microsoft Graph service principal 2026-09-15.
    # 🔴 BUG-169 (2026-09-18): + DelegatedPermissionGrant.ReadWrite.All. Set-PimManagerEasyAuth consents the Manager's
    # sign-in scopes as a tenant-wide oauth2PermissionGrant, and that POST needs exactly this role. Without it the consent
    # failed in EFIF and RIDE, the script WARNED and exited 0, and no human could open either Manager ("Need admin
    # approval") while the build reported success. Id read from the live Graph service principal 2026-09-18.
    [ordered]@{
        'Directory.Read.All'                     = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
        'AppRoleAssignment.ReadWrite.All'        = '06b708a9-e830-4db3-a914-8e69da51d44f'
        'Application.Read.All'                   = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
        'Group.Create'                           = 'bf7b1a76-6e77-406b-b258-bf5c7720e98f'
        'GroupMember.ReadWrite.All'              = 'dbaae8cf-10b5-4b86-a4a1-f871c94c6695'
        'DelegatedPermissionGrant.ReadWrite.All' = '8e8e4742-1d95-4f68-9d56-6ee75648c72a'
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
