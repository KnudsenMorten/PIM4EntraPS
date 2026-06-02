<#
.SYNOPSIS
    PIM-Baseline-Management-CSV - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : PIM-Baseline-Management-CSV.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "PIM Baseline Management"
Write-Output ""
Write-Output "Purpose: Onboarding and management of admin accounts, groups and default PIM assignments"
Write-Output ""
Write-Output "Support: Morten Knudsen - admin@example.invalid | 40 178 179"
Write-Output "***********************************************************************************************"

#------------------------------------------------------------------------------------------------------------
# Loading Functions, Connectivity & Default variables
#------------------------------------------------------------------------------------------------------------
    $ScriptDirectory = $PSScriptRoot
    $global:PathScripts = Split-Path -parent $ScriptDirectory
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
    # One call to Initialize-PlatformAutomationFramework does cert-based
    # Connect-AzAccount, fetches Modern secrets from KV, populates
    # $global:HighPriv_* / $global:AzureTenantId (public contract), and
    # dot-sources Layer-1 platform-defaults.ps1. Zero v1 module imports.
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
    }
    $global:PathScripts = $repoRoot
    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets

<#
    Disconnect-AzAccount
    Connect-AzAccount

    # Microsoft Graph connect with interactive login with the permission defined in the scopes
    Disconnect-MgGraph -ErrorAction SilentlyContinue

    $Scopes = @("Directory.ReadWrite.All",`
                "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
                "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
                "PrivilegedAccess.ReadWrite.AzureADGroup",
                "RoleAssignmentSchedule.ReadWrite.Directory",
                "RoleEligibilitySchedule.ReadWrite.Directory",
                "RoleManagementPolicy.ReadWrite.AzureADGroup",
                "RoleManagement.ReadWrite.Directory",`
                "AdministrativeUnit.ReadWrite.All",
                "User.ReadWrite.All",
                "Group.ReadWrite.All",
                "GroupMember.ReadWrite.All"
                )
    Connect-MicrosoftGraphPS -Scopes $Scopes
#>

######################################################################################################
# PIM Functions
######################################################################################################

    # Loading PIM functions
    Import-Module (Join-Path $PSScriptRoot '..\_shared\PIM-Functions.psm1') -Global -Force -WarningAction SilentlyContinue

######################################################################################################
# PS Module dependency AzResourceGraphPS - built by Morten Knudsen
######################################################################################################

    $ModuleName = "AzResourceGraphPS"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

######################################################################################################
# PS Module dependency AzDcrLogIngestPS - built by Morten Knudsen - contains Get-AzAccessTokenManagement
######################################################################################################

    $ModuleName = "AzLogDcrIngestPS"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

######################################################################################################
# PS Module dependency MicrosoftGraphPS - built by Morten Knudsen
######################################################################################################

    $ModuleName = "MicrosoftGraphPS"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

######################################################################################################
# Variables
######################################################################################################

    # No KV fetch needed -- random per-account passwords are generated inside
    # CreateUpdate-Accounts-From-file-CSV via New-PimRandomPassword.

######################################################################################################
# Include custom settings
######################################################################################################

    # Source Repository
    & (Get-PimCustomScript -Name 'repository')


######################################################################################################
# Building lists of data
######################################################################################################

    $MaxSteps = "11"

    Write-host ""
    Write-host "[ 01 / $($MaxSteps) ] Building list of all Users in Entra ID ... Please Wait !"
    $Global:Users_All_ID = Get-PimAdminsFiltered

    Write-host "[ 02 / $($MaxSteps) ] Building list of all Groups in Entra ID ... Please Wait !"
    $Global:Groups_All_ID = Get-PimGroupsFiltered

    Write-host "[ 03 / $($MaxSteps) ] Building list of all PIM-Groups in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-*") } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 04 / $($MaxSteps) ] Building list of all PIM-Resource Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Resource_SyncAD_Definitions_ID  = $Global:PIM_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-RES*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 05 / $($MaxSteps) ] Building list of all PIM-Service Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Service_SyncAD_Definitions_ID  = $Global:PIM_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-SERV*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 06 / $($MaxSteps) ] Building list of all Administrative Units in Entra ID ... Please Wait !"
    $Global:AU_Definitions_ID = Get-MgDirectoryAdministrativeUnit -All:$true | Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 07 / $($MaxSteps) ] Building list of all Admin Accounts in Entra ID ... Please Wait !"
    $Global:Accounts_Definitions_ID = $Global:Users_All_ID | `
                                                Where-Object { ( ( ($_.UserPrincipalName -like "Admin-*") -or ($_.UserPrincipalName -like "X-Admin*") ) -and ($_.UserPrincipalName -like "*-ID*") ) } | `
                                                Select-Object DisplayName, GivenName, SurName, Id | Sort-Object -Property DisplayName

    Write-host "[ 08 / $($MaxSteps) ] Building list of all Role definitions for Groups in Entra ID ... Please Wait !"
    $Global:Role_Group_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    Write-host "[ 09 / $($MaxSteps) ] Building list of all Role definitions for Administrative Units in Entra ID ... Please Wait !"
    $Global:Role_AU_Definitions_ID = $Global:Role_Group_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "Authentication Administrator") -or `
                                                               ($_.DisplayName -like "Cloud Device Administrator") -or `
                                                               ($_.DisplayName -like "Groups Administrator") -or `
                                                               ($_.DisplayName -like "Helpdesk Administrator") -or `
                                                               ($_.DisplayName -like "License Administrator") -or `
                                                               ($_.DisplayName -like "Password Administrator") -or `
                                                               ($_.DisplayName -like "Printer Administrator") -or `
                                                               ($_.DisplayName -like "SharePoint Administrator") -or `
                                                               ($_.DisplayName -like "Teams Administrator") -or `
                                                               ($_.DisplayName -like "Teams Devices Administrator") -or `
                                                               ($_.DisplayName -like "User Administrator") } | `
                                                Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 10 / $($MaxSteps) ] Building list of all Azure Resources ... Please Wait !"

    $MgInfo = AzMGs-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
    $SubInfo = AzSubscriptions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant

    $Global:AzureResources_Definitions_ID   = @()
    ForEach ($Mg in $MgInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Mg.properties.displayName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Mg.name
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Mg.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    ForEach ($Sub in $SubInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Sub.subsciptionName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Sub.subscriptionId
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Sub.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    Write-host "[ 11 / $($MaxSteps) ] Building list of all Azure Resources Roles ... Please Wait !"
    $Global:AzureResourcesRole_Definitions_ID = Get-AzRoleDefinition | `
                                                Select-Object Name, Description, Id | Sort-Object -Property Name



######################################################################################################################
# AU | Administrative Units | Creation
######################################################################################################################

    CreateUpdate-AdministrativeUnits-From-file-CSV -AdministrativeUnitDefinitionFile $AdministrativeUnitDefinitionFile


######################################################################################################################
# Admin Accounts | Create/Update
######################################################################################################################

    if ($global:WhatIfMode) {
        Write-Host "[WHATIF] Skipping CreateUpdate-Accounts-From-file-CSV (creates/modifies real admin accounts in Entra ID + Exchange Online)." -ForegroundColor Yellow
    } else {
        CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $AccountsDefinitionFile `
                                            -OnlyID
    }

######################################################################################################
# Entra ID Group | PIM for Groups | Create/Update
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Import-csv -Path $global:DeptGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $global:RoleGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $global:TaskGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $global:ProcessGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $global:ServiceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $global:ResourceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array of all PIM for Groups service groups, role groups, org groups
        $Global:PAG_Groups_Definitions_SERVICES = $PAG_Groups_Data | where-object { ($_.GroupName -notlike "PIM-ROLE-*") -and `
                                                                                    ($_.GroupName -notlike "PIM-DEPT-*") -and `
                                                                                    ($_.GroupName -notlike "PIM-ORG-*") -and `
                                                                                    ($_.GroupName -notlike "PIM-CORG-*") -and `
                                                                                    ($_.GroupName -notlike "PIM-PROJECT-*") -and `
                                                                                    ($_.GroupName -notlike "PIM-SRV-*")
                                                                                  }


        $Global:PAG_Groups_Definitions_ROLES = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-ROLE-*") }
        $Global:PAG_Groups_Definitions_DEPT = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-DEPT-*") }
        $Global:PAG_Groups_Definitions_ORG = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-ORG-*") }
        $Global:PAG_Groups_Definitions_CORG = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-CORG-*") }
        $Global:PAG_Groups_Definitions_PROJECT = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-PROJECT-*") }
        $Global:PAG_Groups_Definitions_SRV = $PAG_Groups_Data | where-object { ($_.GroupName -like "PIM-SRV-*") }

        # Scope
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create/Update PIM for Groups
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # Build list of all Administrative Units
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true

        ForEach ($Entry in $Global:PAG_Groups_Definitions)
            {
                $GroupName             = $Entry.GroupName
                $GroupDescription      = $Entry.GroupDescription
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $Owners                = $Entry.Owners
                $IsRoleAssignable      = $Entry.IsRoleAssignable

                write-host ""
                Write-host "Processing group $($GroupName)"
                CreateUpdate-PIM-PAG-Group -GroupName $GroupName `
                                           -GroupDescription $GroupDescription `
                                           -IsRoleAssignable $IsRoleAssignable `
                                           -Owners $Owners

                # Get actual au, based on tags
                $AU = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }

                If ($AU)
                    {
                        $AUName = $AU.AUDisplayName
                    }
                Else
                    {
                        Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                    }

                $AUInfo = $AU_ALL | Where-Object { $_.DisplayName -eq $AUName }
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
                Add-AdministrativeUnit-Member -AuId $AUInfo.Id -AddType Group -ObjectId $GroupInfo.Id
            }



######################################################################################################
# Policies for PIM for Entra ID Roles
######################################################################################################

    # List all PIM for Azure AD Roles policies
    Import-Module Microsoft.Graph.Identity.Governance

    $Uri       = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=rules"
    $EntraID_Roles_Policies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

<#
    EXCLUSIONS

    $EntraID_Roles = Get-MgRoleManagementDirectoryRoleDefinition

    $Scope_Exclude = $EntraID_Roles | Where-Object { ( ($_.DisplayName -eq "Global Administrator") -or `
                                                       ($_.DisplayName -eq "Conditional Access Administrator") -or
                                                       ($_.DisplayName -eq "Privileged Role Administrator") )
                                                   }


    $EntraID_Roles_enriched = @()
    ForEach ($Role in $EntraID_Roles_Policies)
        {
            $ID = $Role.id
     #       $PolicyInfo = Get-MgPolicyRoleManagementPolicy -UnifiedRoleManagementPolicyId $Id -ExpandProperty *
            $Tenant = $Id.Split("_")[1]
            $RoleID = $Id.Split("_")[2]
            $RoleDisplayName = ($EntraID_Roles | Where-Object {$_.Id -eq $RoleID }).DisplayName

            $EntraID_Roles_enriched += [PSCustomObject]@{
                                            Id = $Id
                                            Tenant = $Tenant
                                            RoleId = $RoleId
                                            RoleDisplayName = $RoleDisplayName
                                        }
        }

    $EntraID_Roles_enriched | Where-Object { $_.RoleDisplayName -like "e4839*" }

#>

        ForEach ($Policy in $EntraID_Roles_Policies)
            {
                $Policy_Scope = $Policy 

                Write-host ""
                Write-host "------------------------------------------------------------------"
                write-host ""
                Write-host "Processing Entra ID role $($Policy.id)"
                Write-host ""

                # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview
                $PIM_Policy_Check_Update_Mode = "MicosoftGraph"

                # (1) Entra ID UX - Activation (tab) - Field: Activation maximum duration (hours)
                PIM_Policy_Check_Update -RuleId Expiration_EndUser_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -isExpirationRequired $true `
                                        -maximumDuration "PT8H" <# Sample: PT7H - P1D #>  `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (2) Entra ID UX - Activation (tab) - Field: On activation, require: None, Azure MFA - Require ticket information on activation - Require justification on activation
    <#
                PIM_Policy_Check_Update -RuleId Enablement_Admin_Eligibility -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -enabledRules MultiFactorAuthentication, Justification  `
                                        -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()
    #>

                PIM_Policy_Check_Update -RuleId Enablement_EndUser_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -enabledRules MultiFactorAuthentication, Justification  `
                                        -caller EndUser -Operations all -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (3) Entra ID UX - Activation (tab) - Field: On activation, require: Microsoft Entra Conditional Access authentication context (Preview)
    <#
                PIM_Policy_Check_Update -RuleId AuthenticationContext_EndUser_Assignment -RuleType AuthenticationContextRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -AuthContextIsEnabled $False `
                                        -AuthContextClaimValue "xxx" `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()


                # (4) Entra ID UX - Activation (tab) - Field: Require approval to activate
                PIM_Policy_Check_Update -RuleId Approval_EndUser_Assignment -RuleType ApprovalRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -approvalMode SingleStage `
                                        -isApprovalRequired $True `
                                        -isRequestorJustificationRequired $False `
                                        -isApprovalRequiredForExtension $False `
                                        -isApproverJustificationRequired $False `
                                        -isEscalationEnabled $True `
                                        -escalationTimeInMinutes 30 `
                                        -approvalStageTimeOutInDays 3 `
                                        -primaryApprovers @("admin@example.invalid") -escalationApprovers @("admin@example.invalid","x-admin-mok-id@example.invalid") `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
    #>

                # (5) Entra ID UX - Assignment (tab) - Field: Allow permanent eligible assignment, Expire eligible assignments after
                PIM_Policy_Check_Update -RuleId Expiration_Admin_Eligibility -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -isExpirationRequired $True `
                                        -maximumDuration P365D `
                                        -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                # (6) Entra ID UX - Assignment (tab) - Field: Allow permanent active assignment, Expire active assignments after
                PIM_Policy_Check_Update -RuleId Expiration_Admin_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -isExpirationRequired $true `
                                        -maximumDuration P365D `
                                        -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
            

                # (7) Entra ID UX - Assignment (tab) - Field: Require Azure Multi-Factor Authentication on active assignment, Require justification on active assignment, Require ticket information on activation
                PIM_Policy_Check_Update -RuleId Enablement_Admin_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -enabledRules @() `
                                        -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (9) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Role assignment alert
                PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Admin `
                                        -isDefaultRecipientsEnabled $True `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                # (10) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Requestor  `
                                        -isDefaultRecipientsEnabled $False `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                # (11) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: request to approve a role assignment renewal/extension
                PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Approver  `
                                        -isDefaultRecipientsEnabled $True `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                # (12) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Role assignment alert
                PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Admin  `
                                        -isDefaultRecipientsEnabled $False `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (13) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Notification to the assigned user (assignee)
                PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Requestor  `
                                        -isDefaultRecipientsEnabled $False `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (14) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Request to approve a role assignment renewal/extension
                PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Approver  `
                                        -isDefaultRecipientsEnabled $False `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (15) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Role activation alert
                PIM_Policy_Check_Update -RuleId Notification_Admin_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Admin  `
                                        -isDefaultRecipientsEnabled $True `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (16) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Notification to activated user (requestor)
                PIM_Policy_Check_Update -RuleId Notification_Requestor_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Requestor  `
                                        -isDefaultRecipientsEnabled $False `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                # (17) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Request to approve an activation
                PIM_Policy_Check_Update -RuleId Notification_Approver_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                        -notificationType Email `
                                        -recipientType Approver  `
                                        -isDefaultRecipientsEnabled $True `
                                        -notificationRecipients @() `
                                        -notificationLevel All `
                                        -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
    }





######################################################################################################
# Policies for PIM for Groups
######################################################################################################

    $Groups_All = Get-PimGroupsFiltered

    $Groups_All_Scope = $Groups_All | where-Object { ($_.SecurityEnabled -eq $true) }
    $Groups_All_Scope = $Groups_All_Scope | where-Object { ($_.GroupTypes -notin "DynamicMembership") }
    $Groups_All_Scope = $Groups_All_Scope | where-Object { ($_.OnPremisesSyncEnabled -ne $true) }

    $PIM_Policy_Groups_Target = $Groups_All_Scope | where-Object { ($_.DisplayName -like "PIM-*") } | Sort-Object -Property DisplayName

    Write-host "Getting PIM-policies for all groups ... Please Wait !"
    ForEach ($Group in $PIM_Policy_Groups_Target)
        {
            Write-host ""
            Write-host "------------------------------------------------------------------"
            write-host ""
            Write-host "Processing group $($Group.DisplayName)"
            Write-host ""
            $Uri        = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '$($Group.Id)' and scopeType eq 'Group'&`$expand=rules"
            $PIM_Policy = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject


            ####################################################
            # PIM for Groups - Role: Member
            ####################################################

            Write-host "Checking MEMBER role"
            Write-host ""
            $Policy_Scope = $PIM_Policy[0] # Member

            # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview


            # (1) Entra ID UX - Activation (tab) - Field: Activation maximum duration (hours)
            PIM_Policy_Check_Update -RuleId Expiration_EndUser_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $true `
                                    -maximumDuration "PT8H" <# Sample: PT7H - P1D #>  `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (2) Entra ID UX - Activation (tab) - Field: On activation, require: None, Azure MFA - Require ticket information on activation - Require justification on activation
<#
            PIM_Policy_Check_Update -RuleId Enablement_Admin_Eligibility -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules MultiFactorAuthentication, Justification  `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()
#>

            PIM_Policy_Check_Update -RuleId Enablement_EndUser_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules MultiFactorAuthentication, Justification  `
                                    -caller EndUser -Operations all -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (3) Entra ID UX - Activation (tab) - Field: On activation, require: Microsoft Entra Conditional Access authentication context (Preview)
<#
            PIM_Policy_Check_Update -RuleId AuthenticationContext_EndUser_Assignment -RuleType AuthenticationContextRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -AuthContextIsEnabled $False `
                                    -AuthContextClaimValue "xxx" `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()


            # (4) Entra ID UX - Activation (tab) - Field: Require approval to activate
            PIM_Policy_Check_Update -RuleId Approval_EndUser_Assignment -RuleType ApprovalRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -approvalMode SingleStage `
                                    -isApprovalRequired $True `
                                    -isRequestorJustificationRequired $False `
                                    -isApprovalRequiredForExtension $False `
                                    -isApproverJustificationRequired $False `
                                    -isEscalationEnabled $True `
                                    -escalationTimeInMinutes 30 `
                                    -approvalStageTimeOutInDays 3 `
                                    -primaryApprovers @("admin@example.invalid") -escalationApprovers @("admin@example.invalid","x-admin-mok-id@example.invalid") `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
#>

            # (5) Entra ID UX - Assignment (tab) - Field: Allow permanent eligible assignment, Expire eligible assignments after
            PIM_Policy_Check_Update -RuleId Expiration_Admin_Eligibility -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $True `
                                    -maximumDuration P365D `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (6) Entra ID UX - Assignment (tab) - Field: Allow permanent active assignment, Expire active assignments after
            PIM_Policy_Check_Update -RuleId Expiration_Admin_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $true `
                                    -maximumDuration P365D `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
            

            # (7) Entra ID UX - Assignment (tab) - Field: Require Azure Multi-Factor Authentication on active assignment, Require justification on active assignment, Require ticket information on activation
            PIM_Policy_Check_Update -RuleId Enablement_Admin_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules @() `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (9) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Role assignment alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (10) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (11) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: request to approve a role assignment renewal/extension
            PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (12) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Role assignment alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (13) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Notification to the assigned user (assignee)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (14) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Request to approve a role assignment renewal/extension
            PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (15) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Role activation alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (16) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Notification to activated user (requestor)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (17) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Request to approve an activation
            PIM_Policy_Check_Update -RuleId Notification_Approver_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()


            ####################################################
            # PIM for Groups - Role: Owner
            ####################################################

            Write-host ""
            Write-host "Checking OWNER role"
            Write-host ""
            $Policy_Scope = $PIM_Policy[1] # Owner

            # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview

            # (1) Entra ID UX - Activation (tab) - Field: Activation maximum duration (hours)
            PIM_Policy_Check_Update -RuleId Expiration_EndUser_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $true `
                                    -maximumDuration "PT8H" <# Sample: PT7H - P1D #>  `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (2) Entra ID UX - Activation (tab) - Field: On activation, require: None, Azure MFA - Require ticket information on activation - Require justification on activation
<#
            PIM_Policy_Check_Update -RuleId Enablement_Admin_Eligibility -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules MultiFactorAuthentication, Justification  `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()
#>

            PIM_Policy_Check_Update -RuleId Enablement_EndUser_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules MultiFactorAuthentication, Justification  `
                                    -caller EndUser -Operations all -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (3) Entra ID UX - Activation (tab) - Field: On activation, require: Microsoft Entra Conditional Access authentication context (Preview)
<#
            PIM_Policy_Check_Update -RuleId AuthenticationContext_EndUser_Assignment -RuleType AuthenticationContextRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -AuthContextIsEnabled $False `
                                    -AuthContextClaimValue "xxx" `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()


            # (4) Entra ID UX - Activation (tab) - Field: Require approval to activate
            PIM_Policy_Check_Update -RuleId Approval_EndUser_Assignment -RuleType ApprovalRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -approvalMode SingleStage `
                                    -isApprovalRequired $True `
                                    -isRequestorJustificationRequired $False `
                                    -isApprovalRequiredForExtension $False `
                                    -isApproverJustificationRequired $False `
                                    -isEscalationEnabled $True `
                                    -escalationTimeInMinutes 30 `
                                    -approvalStageTimeOutInDays 3 `
                                    -primaryApprovers @("admin@example.invalid") -escalationApprovers @("admin@example.invalid","x-admin-mok-id@example.invalid") `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
#>

            # (5) Entra ID UX - Assignment (tab) - Field: Allow permanent eligible assignment, Expire eligible assignments after
            PIM_Policy_Check_Update -RuleId Expiration_Admin_Eligibility -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $True `
                                    -maximumDuration P365D `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (6) Entra ID UX - Assignment (tab) - Field: Allow permanent active assignment, Expire active assignments after
            PIM_Policy_Check_Update -RuleId Expiration_Admin_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -isExpirationRequired $false `
                                    -maximumDuration P365D `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
            

            # (7) Entra ID UX - Assignment (tab) - Field: Require Azure Multi-Factor Authentication on active assignment, Require justification on active assignment, Require ticket information on activation
            PIM_Policy_Check_Update -RuleId Enablement_Admin_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -enabledRules @() `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (9) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Role assignment alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (10) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (11) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: request to approve a role assignment renewal/extension
            PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

            # (12) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Role assignment alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (13) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Notification to the assigned user (assignee)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (14) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Request to approve a role assignment renewal/extension
            PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (15) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Role activation alert
            PIM_Policy_Check_Update -RuleId Notification_Admin_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Admin  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (16) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Notification to activated user (requestor)
            PIM_Policy_Check_Update -RuleId Notification_Requestor_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Requestor  `
                                    -isDefaultRecipientsEnabled $False `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

            # (17) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Request to approve an activation
            PIM_Policy_Check_Update -RuleId Notification_Approver_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                    -notificationType Email `
                                    -recipientType Approver  `
                                    -isDefaultRecipientsEnabled $True `
                                    -notificationRecipients @() `
                                    -notificationLevel All `
                                    -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
    }



######################################################################################################################
# Assignment of Roles to Administrative Units
######################################################################################################################

    Assign-Roles-AdministrativeUnits-From-file-CSV -AdministrativeUnitRoleAssignmentsFile $AdministrativeUnitRoleAssignmentsFile


######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################

    Assign-Roles-Groups-From-file-CSV -GroupRoleAssignmentsFile $GroupRoleAssignmentsFile



######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################

    # Set to $null to run all assignments
    $Global:PIM_GroupTag_Scoped_StartsWith = $null     # Use fx. ROLE-MGMT - it uses TargetGroupTag

    Assign-PIMForGroups-From-file-CSV -PIMForGroupsAssignmentsFile $PIMForGroupsAssignmentsFile


######################################################################################################
# Policies for PIM for Azure Resources (Azure Resource Manager)
######################################################################################################

    Write-host "Building list of all Azure Resources ... Please Wait !"

    $MgInfo = AzMGs-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
    $SubInfo = AzSubscriptions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant

    $Global:AzureResources_Definitions_ID   = @()
    ForEach ($Mg in $MgInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Mg.properties.displayName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Mg.name
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Mg.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    ForEach ($Sub in $SubInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Sub.subsciptionName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Sub.subscriptionId
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Sub.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    Write-host "[ 11 / $($MaxSteps) ] Building list of all Azure Resources Roles ... Please Wait !"
    $Global:AzureResourcesRole_Definitions_ID = Get-AzRoleDefinition | `
                                                Select-Object Name, Description, Id | Sort-Object -Property Name

    $Azure_Resources_Data = Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8
    $Azure_Resources_Data = $Azure_Resources_Data | Where-Object { ($_.AzScope -ne "") }

    $ScopeGrouped = $Azure_Resources_Data | Group-Object -Property AzScope

    #------------

    $InitialCollectionRoleInfo = $false

    ForEach ($AzScopeTarget in $ScopeGrouped)
        {

            $AzScope = $AzScopeTarget.group[0].AzScope
            $AzDisplayName = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName

            Write-host "---------------------------------------------------------------------------------------------------"
            Write-host ""
            Write-host "Processing Az Resource Scope [ $($AzDisplayName) ]"
            Write-host "$($AzScope) "

            # List all PIM for Azure resources policies
                $Headers = Get-AzAccessTokenManagement

            # Initial collection
                If ($InitialCollectionRoleInfo -eq $false)
                    {
                        # Role Policies
                        Write-host "  Getting role policies .... Please Wait !"
                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01"
                        $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                        $PIM_Policies_AzResourcesRaw = $Response.Content
                        $PIM_Policies_AzResources = $PIM_Policies_AzResourcesRaw | ConvertFrom-Json
                        $PIM_Policies_AzResources = $PIM_Policies_AzResources.value


                        # Role Definitions at scope
                        Write-host "  Getting role definitions assignments .... Please Wait !"
                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
                        $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                        $PIM_Policies_DefinitionsRaw = $Response.Content
                        $PIM_Policies_Definitions = $PIM_Policies_DefinitionsRaw | ConvertFrom-Json
                        $PIM_Policies_Definitions = $PIM_Policies_Definitions.value

                        $InitialCollectionRoleInfo = $true
                    }

            # Role Policy Assignments
                Write-host "  Getting role policy assignments .... Please Wait !"
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AssignmentRaw = $Response.Content
                $PIM_Policies_Assignments = $PIM_Policies_AssignmentRaw | ConvertFrom-Json
                $PIM_Policies_Assignments = $PIM_Policies_Assignments.value


            ForEach ($Entry in $AzScopeTarget.group)
                {
                    # $AzScope             = $Entry.AzScope
                    # $AzDisplayName       = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName
                    $AzScopePermission   = $Entry.AzScopePermission
                    $AssignmentType      = $Entry.AssignmentType
                    $NumOfDaysWhenExpire = $Entry.NumOfDaysWhenExpire
                    $Permanent           = $Entry.Permanent

                    If ($Permanent -eq "TRUE")
                        {
                            $Permanent = $TRUE
                        }
                    Else
                        {
                            $Permanent = $FALSE
                        }


                    $DefinitionInScope =  $PIM_Policies_Definitions | Where-Object { $_.properties.rolename -eq $AzScopePermission }
                    $PolicyAssignmentInScope = $PIM_Policies_Assignments | Where-Object { $_.properties.roleDefinitionId -match $DefinitionInScope.id }
                    $PolicyInScope = $PolicyAssignmentInScope.properties.policyId.Split("/")[-1]

                    $Policy_Scope = $PolicyAssignmentInScope

                    Write-host ""
                    Write-host "Validating policy rules for role $($AzScopePermission)"

                    # (1) Entra ID UX - Activation (tab) - Field: Activation maximum duration (hours)
                    PIM_Policy_Check_Update -RuleId Expiration_EndUser_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -isExpirationRequired $true `
                                            -maximumDuration "PT8H" <# Sample: PT7H - P1D #>  `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (2) Entra ID UX - Activation (tab) - Field: On activation, require: None, Azure MFA - Require ticket information on activation - Require justification on activation
        <#
                    PIM_Policy_Check_Update -RuleId Enablement_Admin_Eligibility -RuleType EnablementRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                            -enabledRules MultiFactorAuthentication, Justification  `
                                            -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()
        #>

                    PIM_Policy_Check_Update -RuleId Enablement_EndUser_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -enabledRules MultiFactorAuthentication, Justification  `
                                            -caller EndUser -Operations all -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (3) Entra ID UX - Activation (tab) - Field: On activation, require: Microsoft Entra Conditional Access authentication context (Preview)
        <#
                    PIM_Policy_Check_Update -RuleId AuthenticationContext_EndUser_Assignment -RuleType AuthenticationContextRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                            -AuthContextIsEnabled $False `
                                            -AuthContextClaimValue "xxx" `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()


                    # (4) Entra ID UX - Activation (tab) - Field: Require approval to activate
                    PIM_Policy_Check_Update -RuleId Approval_EndUser_Assignment -RuleType ApprovalRule -Policy $Policy_Scope -PIM_API MicrosoftGraph `
                                            -approvalMode SingleStage `
                                            -isApprovalRequired $True `
                                            -isRequestorJustificationRequired $False `
                                            -isApprovalRequiredForExtension $False `
                                            -isApproverJustificationRequired $False `
                                            -isEscalationEnabled $True `
                                            -escalationTimeInMinutes 30 `
                                            -approvalStageTimeOutInDays 3 `
                                            -primaryApprovers @("admin@example.invalid") -escalationApprovers @("admin@example.invalid","x-admin-mok-id@example.invalid") `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
        #>

                    # (5) Entra ID UX - Assignment (tab) - Field: Allow permanent eligible assignment, Expire eligible assignments after
                    PIM_Policy_Check_Update -RuleId Expiration_Admin_Eligibility -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -isExpirationRequired $True `
                                            -maximumDuration P365D `
                                            -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                    # (6) Entra ID UX - Assignment (tab) - Field: Allow permanent active assignment, Expire active assignments after
                    PIM_Policy_Check_Update -RuleId Expiration_Admin_Assignment -RuleType ExpirationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -isExpirationRequired $True `
                                            -maximumDuration P365D `
                                            -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
            

                    # (7) Entra ID UX - Assignment (tab) - Field: Require Azure Multi-Factor Authentication on active assignment, Require justification on active assignment, Require ticket information on activation
                    PIM_Policy_Check_Update -RuleId Enablement_Admin_Assignment -RuleType EnablementRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -enabledRules @() `
                                            -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (9) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Role assignment alert
                    PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Admin `
                                            -isDefaultRecipientsEnabled $True `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                    # (10) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                    PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Requestor  `
                                            -isDefaultRecipientsEnabled $False `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                    # (11) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as eligible to this role: request to approve a role assignment renewal/extension
                    PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Eligibility -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Approver  `
                                            -isDefaultRecipientsEnabled $True `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Eligibility -inheritableSettings @() -enforcedSettings @()

                    # (12) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Role assignment alert
                    PIM_Policy_Check_Update -RuleId Notification_Admin_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Admin  `
                                            -isDefaultRecipientsEnabled $False `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (13) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Notification to the assigned user (assignee)
                    PIM_Policy_Check_Update -RuleId Notification_Requestor_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Requestor  `
                                            -isDefaultRecipientsEnabled $False `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (14) Entra ID UX - Notification (tab) - Field: Send notifications when members are assigned as active to this role: Request to approve a role assignment renewal/extension
                    PIM_Policy_Check_Update -RuleId Notification_Approver_Admin_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Approver  `
                                            -isDefaultRecipientsEnabled $False `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller Admin -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (15) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Role activation alert
                    PIM_Policy_Check_Update -RuleId Notification_Admin_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Admin  `
                                            -isDefaultRecipientsEnabled $True `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (16) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Notification to activated user (requestor)
                    PIM_Policy_Check_Update -RuleId Notification_Requestor_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Requestor  `
                                            -isDefaultRecipientsEnabled $False `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()

                    # (17) Entra ID UX - Notification (tab) - Field: Send notifications when eligible members activate this role: Request to approve an activation
                    PIM_Policy_Check_Update -RuleId Notification_Approver_EndUser_Assignment -RuleType NotificationRule -Policy $Policy_Scope -PIM_API AzureARM `
                                            -notificationType Email `
                                            -recipientType Approver  `
                                            -isDefaultRecipientsEnabled $True `
                                            -notificationRecipients @() `
                                            -notificationLevel All `
                                            -caller EndUser -Operations All -Level Assignment -inheritableSettings @() -enforcedSettings @()
        }
    }


######################################################################################################################
# Assignment of PIM for Azure Resources / Privileged Access Group (PAG)
######################################################################################################################

    Assign-AzResources-Groups-From-file-CSV -GroupAzResourcesAssignmentsFile $GroupAzResourcesAssignmentsFile
                                            

######################################################################################################################
# Admin Accounts | Assignment of Priviledge Access Groups (PAGs)
######################################################################################################################

    $MaxSteps = "11"

    Write-host ""
    Write-host "[ 01 / $($MaxSteps) ] Building list of all Users in Entra ID ... Please Wait !"
    $Global:Users_All_ID = Get-PimAdminsFiltered

    Write-host "[ 02 / $($MaxSteps) ] Building list of all Groups in Entra ID ... Please Wait !"
    $Global:Groups_All_ID = Get-PimGroupsFiltered

    Write-host "[ 03 / $($MaxSteps) ] Building list of all PIM-Groups in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-*") } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 04 / $($MaxSteps) ] Building list of all PIM-Resource Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Resource_SyncAD_Definitions_ID  = $Global:PIM_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-RES*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 05 / $($MaxSteps) ] Building list of all PIM-Service Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Service_SyncAD_Definitions_ID  = $Global:PIM_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-SERV*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 06 / $($MaxSteps) ] Building list of all Administrative Units in Entra ID ... Please Wait !"
    $Global:AU_Definitions_ID = Get-MgDirectoryAdministrativeUnit -All:$true | Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 07 / $($MaxSteps) ] Building list of all Admin Accounts in Entra ID ... Please Wait !"
    $Global:Accounts_Definitions_ID = $Global:Users_All_ID | `
                                                Where-Object { ( ( ($_.UserPrincipalName -like "Admin-*") -or ($_.UserPrincipalName -like "X-Admin*") ) -and ($_.UserPrincipalName -like "*-ID*") ) } | `
                                                Select-Object DisplayName, GivenName, SurName, Id | Sort-Object -Property DisplayName

    Write-host "[ 08 / $($MaxSteps) ] Building list of all Role definitions for Groups in Entra ID ... Please Wait !"
    $Global:Role_Group_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    Write-host "[ 09 / $($MaxSteps) ] Building list of all Role definitions for Administrative Units in Entra ID ... Please Wait !"
    $Global:Role_AU_Definitions_ID = $Global:Role_Group_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "Authentication Administrator") -or `
                                                               ($_.DisplayName -like "Cloud Device Administrator") -or `
                                                               ($_.DisplayName -like "Groups Administrator") -or `
                                                               ($_.DisplayName -like "Helpdesk Administrator") -or `
                                                               ($_.DisplayName -like "License Administrator") -or `
                                                               ($_.DisplayName -like "Password Administrator") -or `
                                                               ($_.DisplayName -like "Printer Administrator") -or `
                                                               ($_.DisplayName -like "SharePoint Administrator") -or `
                                                               ($_.DisplayName -like "Teams Administrator") -or `
                                                               ($_.DisplayName -like "Teams Devices Administrator") -or `
                                                               ($_.DisplayName -like "User Administrator") } | `
                                                Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 10 / $($MaxSteps) ] Building list of all Azure Resources ... Please Wait !"

    $MgInfo = AzMGs-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
    $SubInfo = AzSubscriptions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant

    $Global:AzureResources_Definitions_ID   = @()
    ForEach ($Mg in $MgInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Mg.properties.displayName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Mg.name
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Mg.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    ForEach ($Sub in $SubInfo)
        {
            $Obj = new-object PsCustomObject
            $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Sub.subsciptionName
            $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Sub.subscriptionId
            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Sub.Id
            $Global:AzureResources_Definitions_ID += $Obj
        }

    Write-host "[ 11 / $($MaxSteps) ] Building list of all Azure Resources Roles ... Please Wait !"
    $Global:AzureResourcesRole_Definitions_ID = Get-AzRoleDefinition | `
                                                Select-Object Name, Description, Id | Sort-Object -Property Name

    Assign-Groups-Accounts-From-file-CSV -AccountsAssignmentFile $AccountsAssignmentFile
