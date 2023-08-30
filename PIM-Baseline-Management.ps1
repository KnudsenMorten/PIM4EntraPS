#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "PIM Baseline Management"
Write-Output ""
Write-Output "Purpose: Onboarding and management of admin accounts, groups and default PIM assignments"
Write-Output ""
Write-Output "Support: Morten Knudsen - mok@fjernvarmefyn.dk | 40 178 179"
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


######################################################################################################
# PIM Functions
######################################################################################################

    # Loading PIM functions
    Import-Module "$($global:PathScripts)\FUNCTIONS\PIM-Functions.psm1" -Global -force -WarningAction SilentlyContinue

######################################################################################################
# PS Module dependency AzResourceGraphPS - built by Morten Knudsen
######################################################################################################

    $ModuleName = "AzResourceGraphPS"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

######################################################################################################
# PS Module dependency MicrosoftGraphPS - built by Morten Knudsen
######################################################################################################

    $ModuleName = "MicrosoftGraphPS"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

    # Ensure Microsoft Graph is always updated to latest version !
    Manage-Version-Microsoft.Graph -InstallLatestMicrosoftGraph -Scope AllUsers -CleanupOldMicrosoftGraphVersions

######################################################################################################
# PS Module dependency GMSACredential - credit Ryan Ephgrave
######################################################################################################

    $ModuleName = "GMSACredential"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers

    #-------------------------------------------------------
    # Version add here, as it has been modified from the original source to show the actual code in verbose-mode
    #-------------------------------------------------------
    Function Get-GMSACredential{
        <#
        .SYNOPSIS
        Given a GMSA account, will return a usable PSCredential object
    
        .DESCRIPTION
        Checks AD for the GMSA account information and returns a usable credential. Must be run with an account that has permissions to the password
    
        .PARAMETER GMSAName
        Identity of the GMSA account
    
        .PARAMETER Domain
        Domain logon name of the account
    
        .PARAMETER SearchRoot
        Root to search for the account (most cases can be omitted)
    
        .EXAMPLE
        Get-GMSACredential -GMSAName 'gmsaUser$' -Domain 'Home.Lab'
    
        .NOTES
        .Author: Ryan Ephgrave
        #>
        Param(
            [Parameter(Mandatory=$true)]
            [string]$GMSAName,
            [Parameter(Mandatory=$true)]
            [string]$Domain,
            [Parameter(Mandatory=$false)]
            [string]$SearchRoot = $(([adsisearcher]"").Searchroot.path)
        )

        $dEntryRoot = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $SearchRoot

        $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $dEntryRoot
    
        $searcher.Filter = "(&(name=$($GMSAName.TrimEnd('$')))(ObjectCategory=msDS-GroupManagedServiceAccount))"
        [void]$searcher.PropertiesToLoad.Add('Name')
        [void]$searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
   
        $searcher.SearchRoot.AuthenticationType = 'Sealing'
    
        $Accounts = $searcher.FindAll()
        foreach($a in $accounts){
            if($a.Properties.'msds-managedpassword'){
                $pw = $a.Properties.'msds-managedpassword'
                [Byte[]]$byteBlob = $pw.Foreach({$PSItem})
                $MemoryStream = New-Object System.IO.MemoryStream -ArgumentList (,$byteBlob)
                $Reader = New-Object System.IO.BinaryReader -ArgumentList $MemoryStream
            
                # have to move the reader to the pw offset
                $null = $Reader.ReadInt16()
                $null = $Reader.ReadInt16()
                $null = $Reader.ReadInt32()

                $PWOffset = $Reader.ReadInt16()
                $Length = $byteBlob.Length - $PWOffset
                $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length
                for($i = $PWOffset; $i -le $byteBlob.Length; $i += [System.Text.UnicodeEncoding]::CharSize){
                    $currentChar = [System.BitConverter]::ToChar($byteBlob, $i)
                    if($currentChar -eq [char]::MinValue) { break; }
                    [void]$stringBuilder.Append($currentChar)
                }
                write-verbose ""
                Write-verbose $stringBuilder
                write-verbose ""
                Write-verbose $stringBuilder.ToString()
                return ( New-Object PSCredential -ArgumentList @(
                                        "$($Domain)\$($GMSAName)",
                                        (ConvertTo-SecureString $stringBuilder.ToString() -AsPlainText -Force)
                                        ))
            }
        }
    }

######################################################################################################
# PS Module dependency - beta - Microsoft Graph module
######################################################################################################

    $ModuleName = "Microsoft.Graph.Beta.Identity.Governance"
    $Scope      = "AllUsers"
    Manage-Powershell-Module -ModuleName $ModuleName -Scope AllUsers


######################################################################################################
# Variables
######################################################################################################

    Write-host ""
    Write-host "Getting privileged information from Keyvault ... Please Wait !"

    $AdminAccountsInitialPassword                                         = Get-AzKeyVaultSecret -VaultName $global:KV_HighPriv_KeyVaultName -Name "AdminAccountsInitialPassword" -AsPlainText

    $DeptGroupsDefinitionFile                                             = "$($global:PathScripts)\DATA\PAG-Definitions-Departments.csv"
    $RoleGroupsDefinitionFile                                             = "$($global:PathScripts)\DATA\PAG-Definitions-Roles.csv"
    $TaskGroupsDefinitionFile                                             = "$($global:PathScripts)\DATA\PAG-Definitions-Tasks.csv"
    $ServiceGroupsDefinitionFile                                          = "$($global:PathScripts)\DATA\PAG-Definitions-Services.csv"
    $ProcessGroupsDefinitionFile                                          = "$($global:PathScripts)\DATA\PAG-Definitions-Processes.csv"
    $ResourceGroupsDefinitionFile                                         = "$($global:PathScripts)\DATA\PAG-Definitions-Resources.csv"
    $AdministrativeUnitDefinitionFile                                     = "$($global:PathScripts)\DATA\AU-Definitions.csv"

    $AdministrativeUnitRoleAssignmentsFile                                = "$($global:PathScripts)\DATA\PAG-Assignments-Roles-AUs.csv"
    $GroupRoleAssignmentsFile                                             = "$($global:PathScripts)\DATA\PAG-Assignments-Roles-Groups.csv"
    $GroupAzResourcesAssignmentsFile                                      = "$($global:PathScripts)\DATA\PAG-Assignments-Azure-Resources.csv"
    $AccountsAssignmentFile                                               = "$($global:PathScripts)\DATA\PAG-Assignments-Admins.csv"

    $AccountsDefinitionFile                                               = "$($global:PathScripts)\DATA\Account-Definitions-Admins.csv"

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
    $Notification_Admin_EndUser_notificationRecipients                    = @("IT-Alerts-CloudIdentity@fjernvarmefyn.dk")
    $Notification_Admin_EndUser_isDefaultRecipientsEnabled                = $true 

    $Notification_Requestor_EndUser_Assignment_notificationType           = "Email"
    $Notification_Requestor_EndUser_Assignment_recipientType              = "Requestor"
    $Notification_Requestor_EndUser_Assignment_notificationLevel          = "All"
    $Notification_Requestor_EndUser_Assignment_notificationRecipients     = @("IT-Alerts-CloudIdentity@fjernvarmefyn.dk")
    $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled = $true

    $Notification_Admin_Admin_Eligibility_notificationType                = "Email"
    $Notification_Admin_Admin_Eligibility_recipientType                   = "Admin"
    $Notification_Admin_Admin_Eligibility_notificationLevel               = "All"
    $Notification_Admin_Admin_Eligibility_notificationRecipients          = @("IT-Alerts-CloudIdentity@fjernvarmefyn.dk")
    $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled      = $true

    $Notification_Requestor_Admin_Eligibility_notificationType            = "Email"
    $Notification_Requestor_Admin_Eligibility_recipientType               = "Requestor"
    $Notification_Requestor_Admin_Eligibility_notificationLevel           = "All"
    $Notification_Requestor_Admin_Eligibility_notificationRecipients      = @("IT-Alerts-CloudIdentity@fjernvarmefyn.dk")
    $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled  = $true


######################################################################################################
# Building lists of data
######################################################################################################

    $Context = Set-AzContext -Subscription $global:MainLogAnalyticsWorkspaceSubId

    Import-Module Microsoft.Graph.DeviceManagement.Enrollment

    $MaxSteps = "11"

    Write-host ""
    Write-host "[ 01 / $($MaxSteps) ] Building list of all Users in Entra ID ... Please Wait !"
    $Global:Users_All_ID = Get-MgUser -all:$true

    Write-host "[ 02 / $($MaxSteps) ] Building list of all Groups in Entra ID ... Please Wait !"
    $Global:Groups_All_ID = Get-MgGroup -all:$true

    Write-host "[ 03 / $($MaxSteps) ] Building list of all PAG-Groups in Entra ID ... Please Wait !"
    $Global:PAG_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PAG-*") } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 04 / $($MaxSteps) ] Building list of all PAG-Resource Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PAG_Groups_Resource_SyncAD_Definitions_ID  = $Global:PAG_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PAG-RES*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 05 / $($MaxSteps) ] Building list of all PAG-Service Groups for PIM for AD in Entra ID ... Please Wait !"
    $Global:PAG_Groups_Service_SyncAD_Definitions_ID  = $Global:PAG_Groups_Definitions_ID | `
                                                Where-Object { ($_.DisplayName -like "PAG-SERV*") -and ($_.DisplayName -like "*-S_AD")} | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 06 / $($MaxSteps) ] Building list of all Administrative Units in Entra ID ... Please Wait !"
    $Global:AU_Definitions_ID = Get-MgDirectoryAdministrativeUnit -All:$true | Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 07 / $($MaxSteps) ] Building list of all Admin Accounts in Entra ID ... Please Wait !"
    $Global:Accounts_Definitions_ID = $Global:Users_All_ID | `
                                                Where-Object { ( ( ($_.UserPrincipalName -like "Admin-*") -or ($_.UserPrincipalName -like "X-Admin*") ) -and ($_.UserPrincipalName -like "*-ID*") ) } | `
                                                Select-Object DisplayName, GivenName, SurName, Id | Sort-Object -Property DisplayName

    Write-host "[ 08 / $($MaxSteps) ] Building list of all Role definitions for Groups in Entra ID ... Please Wait !"
    $Global:Role_Group_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

#    $Global:Role_Group_Definitions_ID_raw = AzRoleDefinitions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
#    $Global:Role_Group_Definitions_ID = $Global:Role_Group_Definitions_ID_raw | Where-Object { $_.AssignableScope -eq "/" }

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
# Admin Accounts | Creations
######################################################################################################################

    CreateUpdate-Accounts-From-file-CSV -AccountsDefinitionFile $AccountsDefinitionFile `
                                        -DefaultPassword $AdminAccountsInitialPassword `
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

    Assign-AzResources-Groups-From-file-CSV -GroupAzResourcesAssignmentsFile $GroupAzResourcesAssignmentsFile
                                            

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

