#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "PIM Assignment Revoker"
Write-Output ""
Write-Output "Purpose: Clean-up of Privileged Identity Managemement (PIM) Assignments"
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

    Disconnect-AzAccount
    Connect-AzAccount -TenantId $global:AzureTenantID -WarningAction SilentlyContinue

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
# Building lists of data
######################################################################################################

    Import-Module Microsoft.Graph.DeviceManagement.Enrollment

    $MaxSteps = "14"

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
    # $Global:Role_Group_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    $Global:Role_Group_Definitions_ID_raw = AzRoleDefinitions-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
    $Global:Role_Group_Definitions_ID = $Global:Role_Group_Definitions_ID_raw | Where-Object { $_.AssignableScope -eq "/" }

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


    Write-host "[ 12 / $($MaxSteps) ] Getting all PIM Role Assignments in Entra ID .... Please Wait !"

        # Step 1/2 - Get raw data
            $PIMRoles  = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty *
            $PIMRoles += Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ExpandProperty *

        # Step 2/2 - Build array with better naming
            $PIMRolesArray = @()
        
            ForEach ($Entry in $PIMRoles)
                {
                    If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                            $TimeSpanDays = [math]::Round($TimeSpanDays,0)
                            $SchedulePermanent    = "FALSE"
                        }
                    Else
                        {
                            $TimeSpanDays = "Permanent"
                            $SchedulePermanent    = "TRUE"
                        }
                    If ($Entry.AssignmentType)
                        {
                            $AssignmentType = $Entry.AssignmentType
                        }
                    Else
                        {
                            $AssignmentType = "Eligible"
                        }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $AssignmentType -Force
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
                    $PIMRolesArray += $Obj
                }

    #-----------------------------------------------------------------------------------------------------

    Write-host "[ 13 / $($MaxSteps) ] Getting all PIM Role Assignments in Azure Resources .... Please Wait !"

        # Step 1/2 - Get raw data

            $PIMAzResourceRoleAssignmentsRaw = AzRoleAssignments-Query-AzARG | Query-AzResourceGraph -QueryScope Tenant
            $Global:Role_Group_Definitions_ID = $PIMAzResourceRoleAssignmentsRaw | Where-Object { $_.AssignableScope -ne "/" }

            $PIMAzResourceRoleAssignmentsRaw = @()
            ForEach ($AzScope in $Global:AzureResources_Definitions_ID)
                {
                    Write-host ""
                    Write-host "Retrieving all PIM assignments in Azure Resources .... Please Wait !"
                    Write-host "  $($AzScope.DisplayName) ($($AzScope.Name))"
                    $Headers = Get-AzAccessTokenManagement

                    $AzGraphUri = "https://management.azure.com" + $AzScope.Id + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests?api-version=2020-10-01"
                    $PIMAzResourceRoleAssignmentsRaw += ((invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers).Content)

                    # $AzGraphUri = "https://management.azure.com" + $AzScope.Id + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01"
                    # $PIMAzResourceRoleAssignmentsRaw += ((invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers).Content)
                }

        # Step 2/2 - Build array with better naming

            $PIMAzResourceRoleAssignmentsArray = @()
        
            ForEach ($Entry in $PIMAzResourceRoleAssignments)
                {
                    If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                            $TimeSpanDays = [math]::Round($TimeSpanDays,0)
                            $SchedulePermanent    = "FALSE"
                        }
                    Else
                        {
                            $TimeSpanDays = "Permanent"
                            $SchedulePermanent    = "TRUE"
                        }

                    If ($Entry.targetRoleEligibilityScheduleId)
                        {
                            $AssignmentType = "Eligible"
                        }
                    Else
                        {
                            $AssignmentType = "Assigned"
                        }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $AssignmentType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedOn -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedUsing -Value $Entry.requestorId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ResourceScope -Value $Entry.Scope -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ResourceScopeDisplayName -Value $Entry.expandedProperties.scope.displayName -Force
                    If ($AssignmentType -eq "Assigned")
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.targetRoleAssignmentScheduleId -Force
                        }
                    ElseIf ($AssignmentType -eq "Eligible")
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.targetRoleEligibilityScheduleId -Force
                        }
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalType -Value $Entry.PrincipalType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $Entry.expandedProperties.principal.displayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleId -Value $Entry.RoleDefinitionId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleDisplayName -Value $Entry.expandedProperties.roleDefinition.displayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Justification -Value $Entry.justification -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.ScheduleInfo.StartDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.ScheduleInfo.Expiration.EndDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.ScheduleInfo.Expiration.Type -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.ScheduleInfo.Recurrence -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                    $PIMAzResourceRoleAssignmentsArray += $Obj
                }

            $PIMAzResourceRoleAssignments = ($PIMAzResourceRoleAssignmentsRaw | ConvertFrom-Json).value.properties

    #-----------------------------------------------------------------------------------------------------

    Write-host "[ 14 / $($MaxSteps) ] Getting all PIM Role Assignments in PIM for Groups .... Please Wait !"

        # Step 1/2 - Get raw data

            $PIMGroupEligible = @()
            $PIMGroupActive  = @()

            Foreach ($Group in $Global:Groups_All_ID)
                {
                    Write-host ""
                    Write-host "Getting PIM for Group Eligible Assignments for group $($Group.DisplayName) ... Please Wait !"
                    $PIMGroupEligible  += Get-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -Filter "groupId eq '$($Group.Id)'" -ExpandProperty * -ErrorAction SilentlyContinue

                    Write-host "Getting PIM for Group Active Assignments for group $($Group.DisplayName) ... Please Wait !"
                    $PIMGroupActive  += Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -Filter "groupId eq '$($Group.Id)'" -ExpandProperty *  -ErrorAction SilentlyContinue
                }

        # Step 2/2 - Build array with better naming

            $PIMGroupArray = @()
        
            ForEach ($Entry in $PIMGroupEligible)
                {
                    If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                            $TimeSpanDays = [math]::Round($TimeSpanDays,0)
                            $SchedulePermanent    = "FALSE"
                        }
                    Else
                        {
                            $TimeSpanDays = "Permanent"
                            $SchedulePermanent    = "TRUE"
                        }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value "Eligible" -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Action -Value $Entry.Action -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedBy -Value $Entry.CreatedBy -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name AccessId -Value $Entry.AccessId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.Id -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.MemberType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -Value $Entry.ModifiedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $Entry.Principal.AdditionalProperties.displayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name GroupId -Value $Entry.GroupId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name GroupDisplayName -Value $Entry.Group.DisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.ScheduleInfo.StartDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.ScheduleInfo.Expiration.EndDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.ScheduleInfo.Expiration.Type -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.ScheduleInfo.Recurrence -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Justification -Value $Entry.Justification -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                    $PIMGroupArray += $Obj
                }

            ForEach ($Entry in $PIMGroupActive)
                {
                    If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                            $TimeSpanDays = [math]::Round($TimeSpanDays,0)
                            $SchedulePermanent    = "FALSE"
                        }
                    Else
                        {
                            $TimeSpanDays = "Permanent"
                            $SchedulePermanent    = "TRUE"
                        }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value "Active" -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Action -Value $Entry.Action -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedBy -Value $Entry.CreatedBy -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name AccessId -Value $Entry.AccessId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.Id -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.MemberType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -Value $Entry.ModifiedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $Entry.Principal.AdditionalProperties.displayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name GroupId -Value $Entry.GroupId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name GroupDisplayName -Value $Entry.Group.DisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.ScheduleInfo.StartDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.ScheduleInfo.Expiration.EndDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.ScheduleInfo.Expiration.Type -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.ScheduleInfo.Recurrence -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Justification -Value $Entry.Justification -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                    $PIMGroupArray += $Obj
                }


##########################################################################################################################
# Main Program
##########################################################################################################################

    #-----------------------------------------------------------------------------------------------
    # Step 1 - TYPE of Assignment
    #-----------------------------------------------------------------------------------------------

        $Step1_Choices = [PSCustomObject]@(
                                            [PSCustomObject]@{
                                                Type = "EntraID_Role_Group"
                                                Description = "Entra ID Role Assignment for Group or Admin Account"
                                                },
                                            [PSCustomObject]@{
                                                Type = "Azure_Resource"
                                                Description = "Azure Resource"
                                                },
                                            [PSCustomObject]@{
                                                Type = "PIM_Groups"
                                                Description = "PIM for Groups"
                                                }
                                          )

        $Step1_Result  = $Step1_Choices | Select-Object Description, Type | Out-GridView -Title "PIM Assignment Revoker | Step 1/2: Choose TYPE of Assignment" -PassThru


    #-----------------------------------------------------------------------------------------------
    # Step 2 - SCOPE to delegate
    #-----------------------------------------------------------------------------------------------

    If ($Step1_Result.Type -eq "EntraID_Role_Group")
        {
            # Scoping
            $PIMAssignments = $PIMRolesArray | where-Object { (!([string]::IsNullOrEmpty($_.CreatedUsing))) } | 
                                                Select-Object AssignmentType, `
                                                                RoleDisplayName, `
                                                                PrincipalDisplayName, `
                                                                CreatedDateTime, ` 
                                                                ScheduleStartDateTime, `
                                                                ScheduleExpirationType, `
                                                                ScheduleExpirationEndDateTime, `
                                                                ScheduleTimeSpanDays, `
                                                                SchedulePermanent, `
                                                                RoleId,`
                                                                PrincipalId, `
                                                                CreatedUsing | `
                                                Sort-Object -Property RoleDisplayName

            $DeleteAssignments = $PIMAssignments | Out-GridView -Title 'PIM Assignment Revoker | Select Assignments to Delete' -PassThru

            ForEach ($Entry in $DeleteAssignments)
                {
                    $params = @{
                                    "PrincipalId" = $Entry.PrincipalId
                                    "RoleDefinitionId" = $Entry.RoleId
                                    "Justification" = "Remove active assignment"
                                    "DirectoryScopeId" = "/"
                                    "Action" = "AdminRemove"
                                }

                    If ($Entry.AssignmentType -eq "Eligible")
                        {
                            New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($Entry.AssignmentType -eq "Assigned")
                        {
                            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
                        }
                }
        }
    #---------------------------------------------------------------------------------------------------------------------
    ElseIf ($Step1_Result.Type -eq "Azure_Resource")
        {
            # Scoping
            $PIMAssignments = $PIMAzResourceRoleAssignmentsArray | where-Object { (!([string]::IsNullOrEmpty($_.Id))) } | 
                                                  Select-Object AssignmentType, `
                                                                ResourceScopeDisplayName, `
                                                                RoleDisplayName, `
                                                                PrincipalType, `
                                                                PrincipalDisplayName, `
                                                                CreatedDateTime, ` 
                                                                ScheduleStartDateTime, `
                                                                ScheduleExpirationType, `
                                                                ScheduleExpirationEndDateTime, `
                                                                ScheduleTimeSpanDays, `
                                                                SchedulePermanent, `
                                                                Justification, `
                                                                RoleId,`
                                                                ResourceScope, `
                                                                PrincipalId, `
                                                                Id, `
                                                                CreatedUsing | `
                                                Sort-Object -Property ResourceScopeDisplayName, RoleDisplayName

            $DeleteAssignments = $PIMAssignments | Out-GridView -Title 'Select Assignments to Delete' -PassThru

            ForEach ($Entry in $DeleteAssignments)
                {
                    $Headers = Get-AzAccessTokenManagement

                    $Justification = "IAC: Removing role"

                    $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                properties = @{
                                                                    principalId = $Entry.PrincipalId
                                                                    roleDefinitionId = $Entry.RoleId
                                                                    justification = $Justification
	                                                                requestType = "AdminRemove"
                                                              }
                                            }

                    $Guid = (new-guid).Guid

                    $AzRoleAssignmentBodyJson = $AzRoleAssignmentBody | ConvertTo-Json -Depth 20

                    If ($Entry.AssignmentType -eq "Eligible")
                        {
                            $AzGraphUri = "https://management.azure.com" + $Entry.ResourceScope + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                        }
                    ElseIf ($Entry.AssignmentType -eq "Assigned")
                        {
                            $AzGraphUri = "https://management.azure.com" + $Entry.ResourceScope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                        }

                    invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                }
        }
    #---------------------------------------------------------------------------------------------------------------------
    ElseIf ($Step1_Result.Type -eq "PIM_Groups")
        {

            # Scoping
            $PIMAssignments = $PIMGroupArray | Where-Object { $_.Action -eq "AdminAssign" } | `
                                                  Select-Object AssignmentType, `
                                                                GroupDisplayName, `
                                                                PrincipalDisplayName, `
                                                                Action, `
                                                                AccessId, `
                                                                CreatedDateTime, ` 
                                                                ScheduleStartDateTime, `
                                                                ScheduleExpirationType, `
                                                                ScheduleExpirationEndDateTime, `
                                                                ScheduleTimeSpanDays, `
                                                                SchedulePermanent, `
                                                                GroupId,`
                                                                Id, `
                                                                PrincipalId, `
                                                                CreatedUsing | `
                                                Sort-Object -Property RoleDisplayName

            $DeleteAssignments = $PIMAssignments | Out-GridView -Title 'Select Assignments to Delete' -PassThru

            ForEach ($Entry in $DeleteAssignments)
                {
                    $params = @{
                                    "accessId" = $Entry.AccessId
                                    "PrincipalId" = $Entry.PrincipalId
                                    "GroupId" = $Entry.GroupId
                                    "Justification" = "Remove active assignment"
                                    "Action" = "AdminRemove"
                                }

                    If ($Entry.AssignmentType -eq "Eligible")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($Entry.AssignmentType -eq "Assigned")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params
                        }
                }
        }
