#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "Management & Deployment of Privileged Identity Managemement (PIM)"
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

    # Loading function modules (2LINKIT)
    Import-Module "$($global:PathScripts)\FUNCTIONS\2LINKIT-Functions.psm1" -Global -force  -WarningAction SilentlyContinue

    Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-ConnectDetails.psm1" -Global -force -WarningAction SilentlyContinue
    ConnectDetails
    
    Import-Module "$($global:PathScripts)\FUNCTIONS\Automation-DefaultVariables.psm1" -Global -force -WarningAction SilentlyContinue
    Default_Variables

    # Connecting using modern authentication
    & "$($global:PathScripts)\FUNCTIONS\Connect_Azure.ps1"



    # Microsoft Graph connect with interactive login with the permission defined in the scopes
    Disconnect-MgGraph -ErrorAction SilentlyContinue

    $Scopes = @("RoleManagement.Read.Directory",`
                "Directory.Read.All",`
                "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup"
                "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup"
                "PrivilegedAccess.ReadWrite.AzureADGroup"
                "RoleManagementPolicy.Read.AzureADGroup"
                "RoleManagementPolicy.ReadWrite.AzureADGroup"
                )
    Connect-MicrosoftGraphPS -Scopes $Scopes


######################################################################################################
# Variables
######################################################################################################

    $PIM_Function_Path                                                    = "$($global:PathScripts)\FUNCTIONS\PIM-Functions.psm1"
    $DeptGroupsDefinitionFile                                             = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Departments.csv"
    $RoleGroupsDefinitionFile                                             = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Roles.csv"
    $TaskGroupsDefinitionFile                                             = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Tasks.csv"
    $ServiceGroupsDefinitionFile                                          = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Services.csv"
    $ProcessGroupsDefinitionFile                                          = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Processes.csv"
    $ResourceGroupsDefinitionFile                                         = $Env:OneDrive + "\Desktop\PIM\PAG-Definitions-Resources.csv"
    $AdministrativeUnitDefinitionFile                                     = $Env:OneDrive + "\Desktop\PIM\AU-Definitions.csv"

    $AdministrativeUnitRoleAssignmentsFile                                = $Env:OneDrive + "\Desktop\PIM\PAG-Assignments-Roles-AUs.csv"
    $GroupRoleAssignmentsFile                                             = $Env:OneDrive + "\Desktop\PIM\PAG-Assignments-Roles-Groups.csv"
    $GroupAzResourcesAssignmentsFile                                      = $Env:OneDrive + "\Desktop\PIM\PAG-Assignments-Azure-Resources.csv"
    $AccountsAssignmentFile                                               = $Env:OneDrive + "\Desktop\PIM\PAG-Assignments-Admins.csv"

    $AccountsDefinitionFile                                               = $Env:OneDrive + "\Desktop\PIM\Account-Definitions-Admins.csv"

    $Expiration_EndUser_Assignment_isExpirationRequired                   = $true
    $Expiration_EndUser_Assignment_maximumDuration                        = "P1D"

    $Expiration_Admin_Assignment_isExpirationRequired                     = $true
    $Expiration_Admin_Assignment_maximumDuration                          = "P365D"

    $Expiration_Admin_Eligibility_isExpirationRequired                    = $true
    $Expiration_Admin_Eligibility_maximumDuration                         = "P365D"

    $Enablement_Admin_Assignment_enabledRules                             = @("MultiFactorAuthentication", "Justification")

    $Enablement_Admin_Eligibility_enabledRules                            = @("MultiFactorAuthentication", "Justification")

    $Enablement_EndUser_Assignment_enabledRules                           = @("MultiFactorAuthentication", "Justification")

    $Notification_Admin_EndUser_Assignment_notificationType               = "Email"
    $Notification_Admin_EndUser_recipientType                             = "Admin"
    $Notification_Admin_EndUser_notificationLevel                         = "All"
    $Notification_Admin_EndUser_notificationRecipients                    = @("mok@linkit.net")
    $Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

    $Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
    $Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
    $Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
    $Notification_Requestor_EndUser_Assignment_notificationRecipients     = @("mok@linkit.net")
    $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

    $Notification_Admin_Admin_Eligibility_notificationType                = "Email"
    $Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
    $Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
    $Notification_Admin_Admin_Eligibility_notificationRecipients          = @("mok@linkit.net")
    $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

    $Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
    $Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
    $Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
    $Notification_Requestor_Admin_Eligibility_notificationRecipients      = @("mok@linkit.net")
    $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true

    $DefaultPassword                                                      = 'xWwvJ]6NMw+bWH-d' 


######################################################################################################
# PIM Function library
######################################################################################################

    # Loading PIM functions
    Import-Module $PIM_Function_Path -Global -force -WarningAction SilentlyContinue


######################################################################################################
# Get existing PIM configuration
######################################################################################################

    Write-host "Getting existing PIM configuration .... Please Wait !"

    # Get EntraID Role Definitions
        Import-Module Microsoft.Graph.DeviceManagement.Enrollment
        $Global:RoleDefinitionList = Get-MgRoleManagementDirectoryRoleDefinition

    # get existing PIM roles
        $EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
        $AssignedPIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *


######################################################################################################################
# AU | Administrative Units | Creation
######################################################################################################################

    CreateUpdate-AdministrativeUnits-From-file-CSV -AdministrativeUnitDefinitionFile $AdministrativeUnitDefinitionFile

######################################################################################################################
# Admin Accounts | Creations
######################################################################################################################

    CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $AccountsDefinitionFile `
                                        -DefaultPassword 'xWwvJ]6NMw+bWH-d' `
                                        -OnlyID

######################################################################################################
# PAG | PIM for Groups | Privileged Access Group (PAG) - Creation
######################################################################################################

    CreateUpdate-PIM-for-Groups-From-file-CSV -DeptGroupsDefinitionFile $DeptGroupsDefinitionFile `
                                              -RoleGroupsDefinitionFile $RoleGroupsDefinitionFile `
                                              -TaskGroupsDefinitionFile $TaskGroupsDefinitionFile `
                                              -ServiceGroupsDefinitionFile $ServiceGroupsDefinitionFile `
                                              -ProcessGroupsDefinitionFile $ProcessGroupsDefinitionFile `
                                              -ResourceGroupsDefinitionFile $ResourceGroupsDefinitionFile

######################################################################################################
# Policies for PIM for Azure AD roles
######################################################################################################

    CreateUpdate-Policies-PIM-Roles -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                    -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                    -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                    -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                    -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                    -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                    -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                    -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                    -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                    -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                    -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                    -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                    -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                    -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                    -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                    -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                    -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                    -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                    -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                    -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                    -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                    -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                    -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                    -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                    -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                    -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                    -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                    -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                    -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


######################################################################################################################
# Assignment of Roles to Administrative Units
######################################################################################################################

    Assign-Roles-AdministrativeUnits-From-file-CSV -AdministrativeUnitRoleAssignmentsFile $AdministrativeUnitRoleAssignmentsFile


######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################

    Assign-Roles-Groups-From-file-CSV -GroupRoleAssignmentsFile $GroupRoleAssignmentsFile


######################################################################################################################
# Assignment of PIM for Azure Resources / Privileged Access Group (PAG)
######################################################################################################################

    Assign-AzResources-Groups-From-file-CSV -GroupAzResourcesAssignmentsFile $GroupAzResourcesAssignmentsFile `
                                            

######################################################################################################################
# Admin Accounts | Assignment of Priviledge Access Groups (PAGs)
######################################################################################################################

    Assign-Groups-Accounts-From-file-CSV -AccountsAssignmentFile $AccountsAssignmentFile


######################################################################################################
# Policies for PIM for Azure Resources (Azure Resource Manager)
######################################################################################################

    CreateUpdate-Policies-PIM-AzResources   -GroupAzResourcesAssignmentsFile $GroupAzResourcesAssignmentsFile `
                                            -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                            -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                            -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                            -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                            -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                            -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                            -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                            -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                            -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                            -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                            -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                            -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                            -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                            -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                            -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                            -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                            -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                            -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                            -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                            -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                            -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                            -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                            -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                            -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                            -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                            -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                            -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                            -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                            -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


######################################################################################################
# Policies for PIM for Groups
######################################################################################################

    CreateUpdate-Policies-PIM-Groups -Expiration_EndUser_Assignment_isExpirationRequired $Expiration_EndUser_Assignment_isExpirationRequired `
                                     -Expiration_EndUser_Assignment_maximumDuration $Expiration_EndUser_Assignment_maximumDuration `
                                     -Expiration_Admin_Assignment_isExpirationRequired $Expiration_Admin_Assignment_isExpirationRequired `
                                     -Expiration_Admin_Assignment_maximumDuration $Expiration_Admin_Assignment_maximumDuration `
                                     -Expiration_Admin_Eligibility_isExpirationRequired $Expiration_Admin_Eligibility_isExpirationRequired `
                                     -Expiration_Admin_Eligibility_maximumDuration $Expiration_Admin_Eligibility_maximumDuration `
                                     -Enablement_Admin_Assignment_enabledRules $Enablement_Admin_Assignment_enabledRules `
                                     -Enablement_Admin_Eligibility_enabledRules $Enablement_Admin_Eligibility_enabledRules `
                                     -Enablement_EndUser_Assignment_enabledRules $Enablement_EndUser_Assignment_enabledRules `
                                     -Notification_Admin_EndUser_Assignment_notificationType $Notification_Admin_EndUser_Assignment_notificationType `
                                     -Notification_Admin_EndUser_recipientType $Notification_Admin_EndUser_recipientType `
                                     -Notification_Admin_EndUser_notificationLevel $Notification_Admin_EndUser_notificationLevel `
                                     -Notification_Admin_EndUser_notificationRecipients $Notification_Admin_EndUser_notificationRecipients `
                                     -Notification_Admin_EndUser_isDefaultRecipientsEnabled $Notification_Admin_EndUser_isDefaultRecipientsEnabled `
                                     -Notification_Requestor_EndUser_Assignment_notificationType $Notification_Requestor_EndUser_Assignment_notificationType `
                                     -Notification_Requestor_EndUser_Assignment_recipientType $Notification_Requestor_EndUser_Assignment_recipientType `
                                     -Notification_Requestor_EndUser_Assignment_notificationLevel $Notification_Requestor_EndUser_Assignment_notificationLevel `
                                     -Notification_Requestor_EndUser_Assignment_notificationRecipients $Notification_Requestor_EndUser_Assignment_notificationRecipients `
                                     -Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled `
                                     -Notification_Admin_Admin_Eligibility_notificationType $Notification_Admin_Admin_Eligibility_notificationType `
                                     -Notification_Admin_Admin_Eligibility_recipientType $Notification_Admin_Admin_Eligibility_recipientType `
                                     -Notification_Admin_Admin_Eligibility_notificationLevel $Notification_Admin_Admin_Eligibility_notificationLevel `
                                     -Notification_Admin_Admin_Eligibility_notificationRecipients $Notification_Admin_Admin_Eligibility_notificationRecipients `
                                     -Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled `
                                     -Notification_Requestor_Admin_Eligibility_notificationType $Notification_Requestor_Admin_Eligibility_notificationType `
                                     -Notification_Requestor_Admin_Eligibility_recipientType $Notification_Requestor_Admin_Eligibility_recipientType `
                                     -Notification_Requestor_Admin_Eligibility_notificationLevel $Notification_Requestor_Admin_Eligibility_notificationLevel `
                                     -Notification_Requestor_Admin_Eligibility_notificationRecipients $Notification_Requestor_Admin_Eligibility_notificationRecipients `
                                     -Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled


#----------------------------------------------------------------------------------------

# Goal: Detect Eligible Role Assignment, not defined in data - for clean-up purpose

    # Entra User & Groups
        $EntraID_Users = Get-MgUser-AllProperties-AllUsers
        $EntraID_Groups = Get-MgGroup -all:$true

    # PIM roles
        $EligiblePIMRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
        $ActivePIMRoles = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *

    # EligiblePIMRoles | Build Array with PrincipalId
        $EligiblePIMRolesArray = @()
        
        ForEach ($Entry in $EligiblePIMRoles)
            {
                If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                    {
                        $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                        $TimeSpanDays = [math]::Round($TimeSpanDays)
                        $SchedulePermanent    = "FALSE"
                    }
                Else
                    {
                        $TimeSpanDays = "Permanent"
                        $SchedulePermanent    = "TRUE"
                    }

                $Obj = new-object PSCustomObject
                $Obj | Add-Member -MemberType NoteProperty -Name Type -Value "Active" -Force
                $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name CreatedUsing -Value $Entry.CreatedUsing -Force
                $Obj | Add-Member -MemberType NoteProperty -Name DirectoryScopeId -Value $Entry.DirectoryScopeId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.Id -Force
                $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.MemberType -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -Value $Entry.ModifiedDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $Entry.Principal.AdditionalProperties.displayName -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleId -Value $Entry.RoleDefinitionId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleDisplayName -Value $Entry.RoleDefinition.DisplayName -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleResourceScopes -Value $Entry.RoleDefinition.ResourceScopes -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleInheritsPermissionsFrom -Value $Entry.RoleDefinition.InheritsPermissionsFrom -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RolePermissions -Value $Entry.RoleDefinition.RolePermissions -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleIsBuiltIn -Value $Entry.RoleDefinition.IsBuiltIn -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleIsEnabled -Value $Entry.RoleDefinition.IsEnabled -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.ScheduleInfo.StartDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.ScheduleInfo.Expiration.EndDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.ScheduleInfo.Expiration.Type -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.ScheduleInfo.Recurrence -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                $EligiblePIMRolesArray += $Obj
            }

    # ActivePIMRoles | Build Array with PrincipalId
        $ActivePIMRolesArray = @()
        
        ForEach ($Entry in $ActivePIMRoles)
            {
                If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                    {
                        $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                        $TimeSpanDays = [math]::Round($TimeSpanDays)
                        $SchedulePermanent    = "FALSE"
                    }
                Else
                    {
                        $TimeSpanDays = "Permanent"
                        $SchedulePermanent    = "TRUE"
                    }

                $Obj = new-object PSCustomObject
                $Obj | Add-Member -MemberType NoteProperty -Name Type -Value "Active" -Force
                $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name CreatedUsing -Value $Entry.CreatedUsing -Force
                $Obj | Add-Member -MemberType NoteProperty -Name DirectoryScopeId -Value $Entry.DirectoryScopeId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.Id -Force
                $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.MemberType -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -Value $Entry.ModifiedDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $Entry.Principal.AdditionalProperties.displayName -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleId -Value $Entry.RoleDefinitionId -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleDisplayName -Value $Entry.RoleDefinition.DisplayName -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleResourceScopes -Value $Entry.RoleDefinition.ResourceScopes -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleInheritsPermissionsFrom -Value $Entry.RoleDefinition.InheritsPermissionsFrom -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RolePermissions -Value $Entry.RoleDefinition.RolePermissions -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleIsBuiltIn -Value $Entry.RoleDefinition.IsBuiltIn -Force
                $Obj | Add-Member -MemberType NoteProperty -Name RoleIsEnabled -Value $Entry.RoleDefinition.IsEnabled -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.ScheduleInfo.StartDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.ScheduleInfo.Expiration.EndDateTime -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.ScheduleInfo.Expiration.Type -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.ScheduleInfo.Recurrence -Force
                $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                $ActivePIMRolesArray += $Obj
            }

        # Build deviation-list - things can be made manually
            $GroupRoleAssignmentsData = Import-csv -Path $GroupRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

            # remove empty lines
            $GroupRoleAssignmentsData = $GroupRoleAssignmentsData | Where { $_.GroupName -ne "" }

        #--------------------------------------------

        # Active Assignments
            $CompliantRoleAssignmentsGlobal = @()
            ForEach ($Entry in $ActivePIMRolesArray)
                {
                    ForEach ($ManagedEntry in $GroupRoleAssignmentsData)
                        {
                            If ( ($ManagedEntry.GroupName -eq $Entry.PrincipalDisplayName) -and `
                                 ($ManagedEntry.RoleDefinitionName -eq $Entry.RoleDisplayName) -and `
                                 ($ManagedEntry.AssignmentType -eq "Active") -and `
                                 ($ManagedEntry.NumOfDaysWhenExpire -eq $Entry.ScheduleTimeSpanDays) -and `
                                 ($ManagedEntry.Permanent -eq $Entry.SchedulePermanent) -and `
                                 ($Entry.DirectoryScopeId -eq "/") )
                                {
                                    $CompliantRoleAssignmentsGlobal += $Entry
                                }
                        }
                }

            # Incompliant Active Role Assignments
            $IncompliantRoleAssignmentsGlobal = $ActivePIMRolesArray | `
                                                Where-Object { ($_.Id -notin $CompliantRoleAssignmentsGlobal.Id) }

            $DeleteActiveAssignments = $IncompliantRoleAssignmentsGlobal | Out-GridView -Title 'Select Active Assignments to delete' -PassThru

            ForEach ($Entry in $DeleteActiveAssignments)
                {
                    $params = @{
                                  "PrincipalId" = $Entry.PrincipalId
                                  "RoleDefinitionId" = $Entry.RoleId
                                  "Justification" = "Remove active assignment"
                                  "DirectoryScopeId" = "/"
                                  "Action" = "AdminRemove"
                               }

                    New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
                }

        #--------------------------------------------

        # Eligible Assignments
            $CompliantRoleEligibleGlobal = @()
            ForEach ($Entry in $EligiblePIMRolesArray)
                {
                    ForEach ($ManagedEntry in $GroupRoleAssignmentsData)
                        {
                            If ( ($ManagedEntry.GroupName -eq $Entry.PrincipalDisplayName) -and `
                                 ($ManagedEntry.RoleDefinitionName -eq $Entry.RoleDisplayName) -and `
                                 ($ManagedEntry.AssignmentType -eq "Eligible") -and `
                                 ($ManagedEntry.NumOfDaysWhenExpire -eq $Entry.ScheduleTimeSpanDays) -and `
                                 ($ManagedEntry.Permanent -eq $Entry.SchedulePermanent) -and `
                                 ($Entry.DirectoryScopeId -eq "/") )
                                {
                                    $CompliantRoleEligibleGlobal += $Entry
                                }
                        }
                }

            # Incompliant Eligible Role Assignments
            $IncompliantRoleEligibleGlobal = $EligiblePIMRolesArray | `
                                                Where-Object { ($_.Id -notin $CompliantRoleEligibleGlobal.Id) }

            $DeleteEligibleAssignments = $IncompliantRoleEligible | Out-GridView -Title 'Select Eligible Assignments to delete' -PassThru

            ForEach ($Entry in $DeleteEligibleAssignments)
                {
                    $params = @{
                                  "PrincipalId" = $Entry.PrincipalId
                                  "RoleDefinitionId" = $Entry.RoleId
                                  "Justification" = "Remove eligible assignment"
                                  "DirectoryScopeId" = "/"
                                  "Action" = "AdminRemove"
                               }

                    New-MgRoleManagementDirectoryRoleEligibleScheduleRequest -BodyParameter $params
                }


            #----------------------------------------------------------------------------

            ForEach ($Entry in $PAG_Assignments_Data)
                {
                    $GroupName           = $Entry.GroupName
                    $RoleDefinitionName  = $Entry.RoleDefinitionName
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

                    # Workaround due to nesting is NOT supported on Active Role Assignment
                    # Nesting is currently not supported for groups that can be assigned to a role.
                    # New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest
                    # Solution - Assign Role directly to PAG group, if AssignmentType = Active


                    If ($RoleDefinitionName)
                        {
                            Create-PIM-Group-Role -GroupName $GroupName `
                                                  -RoleDefinitionName $RoleDefinitionName `
                                                  -AssignmentType $AssignmentType `
                                                  -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                                  -Permanent:$Permanent
                        }
                }


#----------------------------------------------------------------------------------------

    # AzResource - DisplayName, Name, Id
        $MgInfo = AzMGs-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
        $SubInfo = AzSubscriptions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant

        $Array = @()
        ForEach ($Mg in $MgInfo)
            {
                $Obj = new-object PsCustomObject
                $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Mg.properties.displayName
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Mg.name
                $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Mg.Id
                $Array += $Obj
            }

        ForEach ($Sub in $SubInfo)
            {
                $Obj = new-object PsCustomObject
                $Obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Sub.subsciptionName
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $Sub.subscriptionId
                $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Sub.Id
                $Array += $Obj
            }

        $ResourceInfoArray = $Array

    # Get AU scope Id
        Import-Module Microsoft.Graph.Identity.DirectoryManagement

        $AUs = Get-MgDirectoryAdministrativeUnit

    # Get Role definition Id
        $Global:RoleDefinitionList

    # Get Group Principal Id
        $Group = Get-MgGroup -Filter "DisplayName eq '$($PAG_Groupname)'"
        $principalId = $Group.Id



#--------------------------------------------------------------------------
# User Activates Eligible Department

$Group = $EntraID_Groups | Where-Object { $_.DisplayName -eq "PAG-DEPT-IT-ADM-Operation-L4-HighPrivAdmin-ID" }

$params = @{
	groupId = $Group.Id
	action = "SelfActivate"
	justification = "I need to work"
    principalId = $MyId.Id
    "ScheduleInfo" = @{
      "StartDateTime" = Get-Date
      "Expiration" = @{
                        "Type" = "AfterDuration"
                        "Duration" = "PT8H"
                      }
  }
}

New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params

#----------------
$MyId = $EntraID_Users | Where-Object { $_.UserPrincipalName -eq "admin@example.invalid" }
$Role = $Global:RoleDefinitionList | Where-Object { $_.DisplayName -eq "Application Administrator" }

$params = @{
  "PrincipalId" = $MyId.Id
  "RoleDefinitionId" = $Role.id
  "Justification" = "I need to work"
  "DirectoryScopeId" = "/"
  "Action" = "SelfActivate"
  "ScheduleInfo" = @{
    "StartDateTime" = Get-Date
    "Expiration" = @{
                       "Type" = "AfterDuration"
                       "Duration" = "PT8H"
                    }
   }
}
New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
