#Requires -Version 5.1
<#
.SYNOPSIS
    DBINIT-MEMBERSHIP (framework 4.5 point 5; OWNER DECISION 2026-11-05 "Grant updater the right") -- THE ONE LIST of
    Microsoft Graph application permissions the UPDATER's identity (ca-pim-update's system-assigned managed identity) holds,
    and the pure check of a token against it.

.DESCRIPTION
    Read by THREE places, so they always agree:
      * the install: tools/setup/_PimSetupShared.ps1 (Get-PimGraphAppRoleMap -RoleSet Updater) <- Deploy-PimUpdateJob.ps1
        grants it with Grant-PimMiGraph -RoleSet Updater;
      * the ops / Support-app grant at existing installs (dot-source THIS file, call Get-PimUpdaterGraphAppRoles);
      * the updater itself (tools/pim-engine/update-job-entry.ps1 step 2e-quater): it reads the roles in its own Graph
        token and REPORTS a missing one (Get-PimUpdaterGraphRoleCheck) -- it can never grant itself.
    Why each: the updater READS whether the database job's identity (id-pim-dbinit) is a member of the SQL admin group and
    REPORTS it (engine/_shared/PIM-DbInitMembership.ps1 Invoke-PimDbInitMembershipReport). SECURE-WEB-1 (Invardia / owner
    2026-11-14; framework G5a 2026-11-15): it holds NO PIM-for-Groups right any more (neither the ReadWrite -- tenant-wide --
    nor the Read of the assignments); the membership is read through the identity's memberOf only. id-pim-dbinit is a PERMANENT DIRECT member, set ONCE by setup (tools/setup/Setup-PimContainers.ps1:
    Invoke-PimDbInitMembershipBeforeStart -DirectOnly) or a recorded Invardia Support-app step; the updater never writes it.
    The ENGINE keeps its own PIM-for-Groups rights (the product function, tools/setup/_PimSetupShared.ps1). APP-REG-OWNER (framework SECAUDIT-1a item 2): the updater
    proves, as an OWNER, that it can change PIM's product app registrations (engine/_shared/PIM-AppRegOwner.ps1) --
    Application.ReadWrite.OwnedBy.
    PURE: no network. ASCII only; PS 5.1 + 7; no modules.
#>
Set-StrictMode -Off

function Get-PimUpdaterGraphAppRoles {
    <#
      PURE. The updater's Graph application permissions, name -> appRoleId (ordered) -- EXACTLY framework 4.5 G5 (Invardia,
      binding 2026-11-05, updated the same day with GroupMember.Read.All and Application.Read.All (FIVE rights), and on 2026-11-07
      with Application.ReadWrite.OwnedBy (SIX, SECAUDIT-1a item 2); SI proved at a customer that the PIM-for-Groups rights alone add and read back a member of a
      role-assignable group). Ids from the live Microsoft Graph service principal (the same ids as the maps in
      tools/setup/_PimSetupShared.ps1).
        (framework G5a, Invardia 2026-11-15, 3.1.26: PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup,
         PrivilegedAssignmentSchedule.Read.AzureADGroup and RoleManagementPolicy.Read.AzureADGroup are REMOVED -- the updater
         no longer writes, renews or reads PIM-for-Groups assignments; its one membership read is the plain memberOf below)
        GroupMember.Read.All                                 READ ONLY: the SQL admin group itself (GET /groups/<id>) and the
                                                             identity's memberOf -- the read-back of a direct member and the
                                                             setup step 'db-job' (G5 update, Invardia 2026-11-05: without a group
                                                             read the step stayed 'unknown' at a live install)
        Application.Read.All                                 READ ONLY: the member-side read GET /servicePrincipals/{id}/memberOf
                                                             -- reading a SERVICE PRINCIPAL (the database job identity) needs it
                                                             besides GroupMember.Read.All (framework 4.5 G5, Invardia
                                                             2026-11-05, cea85308)
        Application.ReadWrite.OwnedBy                        APP-REG-OWNER (framework SECAUDIT-1a item 2, Invardia ruling
                                                             2026-11-07; 3.0.54): writes ONLY to the app registrations the
                                                             updater OWNS -- PIM's product registrations, after a recorded
                                                             support step made it an owner (tools/setup/_PimAppRegOwner.ps1).
                                                             The updater's one write with it is the proof PATCH
                                                             (engine/_shared/PIM-AppRegOwner.ps1); it never adds itself as an
                                                             owner and never grants itself a role.
      NEVER a directory-role right, no group WRITE right and (SECURE-WEB-1 / G5a) no PIM-for-Groups right at all
      (PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup is tenant-wide). Never Application.ReadWrite.All (tenant-wide).
      FOUR rights since 3.1.26 (was seven).
    #>
    return [ordered]@{
        'GroupMember.Read.All'                                = '98830695-27a2-44f7-8c18-0c3ebc9698f6'
        'Application.Read.All'                                = '9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30'
        'Application.ReadWrite.OwnedBy'                       = '18a4783c-866b-4cc7-a460-3d5e5662c884'
        # RIGHTS-LIVE-1 (owner rights decision 2026-11-09 "approved with A"; SEVEN): READ ONLY, basic profile -- the converge
        # step's alert recipients read each SuperAdmin's mail address (tools/setup/Set-PimAlertRecipients.ps1:
        # GET users/<upn>?$select=mail,userPrincipalName, run by engine/_shared/PIM-ConvergeDefaults.ps1 from the updater)
        'User.ReadBasic.All'                                  = '97235f07-e226-4f63-ace3-39588e11d3a1'
    }
}
function Get-PimUpdaterGraphRoleCheck {
    <#
      PURE. Which of the updater's permissions (Get-PimUpdaterGraphAppRoles) are in a Graph access token's 'roles' claim.
      -Token: the bearer token (a JWT; only its payload is read, never logged). Returns @{ known; held[]; missing[]; reason }.
      known $false = the token could not be read (nothing is claimed missing then).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Token)
    $o = @{ known = $false; held = @(); missing = @(); reason = '' }
    $want = @((Get-PimUpdaterGraphAppRoles).Keys)
    try {
        $parts = "$Token".Split('.')
        if ($parts.Count -lt 2) { $o.reason = 'no Graph token'; return $o }
        $p = $parts[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        $roles = @(); if ($c.PSObject.Properties['roles']) { $roles = @($c.roles | ForEach-Object { "$_" }) }
        $o.known = $true
        $o.held = @($want | Where-Object { $roles -contains $_ })
        $o.missing = @($want | Where-Object { $roles -notcontains $_ })
        $o.reason = $(if ($o.missing.Count) { "the updater's identity is missing the Graph application permission(s) $($o.missing -join ', ') -- setup grants them (Deploy-PimUpdateJob), the updater never grants itself" } else { 'the updater holds every Graph permission it needs' })
    } catch { $o.known = $false; $o.reason = 'the Graph token could not be read' }
    return $o
}
