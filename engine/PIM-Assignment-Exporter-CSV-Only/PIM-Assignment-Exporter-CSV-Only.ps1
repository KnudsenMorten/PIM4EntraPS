<#
.SYNOPSIS
    PIM-Assignment-Exporter-CSV-Only - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : PIM-Assignment-Exporter-CSV-Only.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "PIM Assignment Exporter"
Write-Output ""
Write-Output "Purpose: Export of Privileged Identity Managemement (PIM) Assignments"
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
# Building lists of data
######################################################################################################

    $MaxSteps = "14"

    Write-host ""
    Write-host "[ 01 / $($MaxSteps) ] Building list of all Users in Entra ID ... Please Wait !"
    $Global:Users_All_ID = Get-PimAdminsFiltered

    Write-host "[ 02 / $($MaxSteps) ] Building list of all Groups in Entra ID ... Please Wait !"
    $Global:Groups_All_ID = Get-PimGroupsFiltered

    Write-host "[ 03 / $($MaxSteps) ] Building list of all Service Principals in Entra ID ... Please Wait !"
    $Global:ServicePrincipals_All_ID = Get-MgServicePrincipal -all:$true

    Write-host "[ 04 / $($MaxSteps) ] Building list of all PIM-Groups in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-*") } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 05 / $($MaxSteps) ] Building list of all Administrative Units in Entra ID ... Please Wait !"
    $Global:AU_Definitions_ID = Get-MgDirectoryAdministrativeUnit -All:$true | Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 06 / $($MaxSteps) ] Building list of all Admin Accounts in Entra ID ... Please Wait !"
    $Global:Accounts_Definitions_ID = $Global:Users_All_ID | `
                                                Where-Object { ( ( ($_.UserPrincipalName -like "Admin-*") -or ($_.UserPrincipalName -like "X-Admin*") ) -and ($_.UserPrincipalName -like "*-ID*") ) } | `
                                                Select-Object DisplayName, GivenName, SurName, Id | Sort-Object -Property DisplayName

    Write-host "[ 07 / $($MaxSteps) ] Building list of all Role definitions for Groups in Entra ID ... Please Wait !"
    $Global:Role_Group_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    Write-host "[ 08 / $($MaxSteps) ] Building list of all Role definitions for Administrative Units in Entra ID ... Please Wait !"
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

    Write-host "[ 09 / $($MaxSteps) ] Building list of all Azure Resources ... Please Wait !"

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

    Write-host "[ 10 / $($MaxSteps) ] Building list of all Azure Resources Roles ... Please Wait !"
    $Global:AzureResourcesRole_Definitions_ID = Get-AzRoleDefinition | `
                                                Select-Object Name, Description, Id | Sort-Object -Property Name


    Write-host "[ 11 / $($MaxSteps) ] Getting all PIM Role Assignments in Entra ID .... Please Wait !"

        # Step 1/2 - Get raw data
            $PIMRoles  = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
            $PIMRoles += Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All

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

                        # Try fetching as user
                        $principal = $Global:Users_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                        If ($Principal -eq $null) {
                            # Try group
                            $principal = $Global:Groups_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                                If ($Principal -eq $null) {
                                    # Try service principal
                                    $principal = $Global:ServicePrincipals_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                                }
                        }
                        $PrincipalDisplayName = $principal.DisplayName
                        
                        $RoleDefinitionId = $Entry.roleDefinitionId.Split('/')[-1]
                        $RoleDisplayName = ($Global:Role_Group_Definitions_ID | where-object { $_.Id -eq $RoleDefinitionId }).DisplayName
                        If ($RoleDisplayName -eq $null)
                            {
                                $RoleDisplayName = ($Global:AzureResourcesRole_Definitions_ID | where-object { $_.Id -eq $RoleDefinitionId }).Name
                            }
                        
                        If ($Entry.DirectoryScopeId -like "/administrativeUnits/*") {
                            $AUID = $Entry.DirectoryScopeId.Split('/')[-1]
                            $DirectoryScopeDisplayName = "/AdministrativeUnits/" + ($Global:AU_Definitions_ID | Where-Object { $_.id -eq $AUId }).DisplayName
                        } Else {
                            $DirectoryScopeDisplayName = "/ (tenant-wide)"
                        }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $AssignmentType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedUsing -Value $Entry.CreatedUsing -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name DirectoryScope -Value $DirectoryScopeDisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.Id -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.MemberType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ModifiedDateTime -Value $Entry.ModifiedDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name DirectoryScopeId -Value $Entry.DirectoryScopeId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $PrincipalDisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleId -Value $Entry.RoleDefinitionId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleDisplayName -Value $RoleDisplayName -Force
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

    Write-host "[ 12 / $($MaxSteps) ] Getting all PIM Role Assignments in Azure Resources .... Please Wait !"

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

                    $AzGraphUri = "https://management.azure.com" + $AzScope.Id + "/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"
                    $PIMAzResourceRoleAssignmentsRaw += ((invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers).Content)

                    $AzGraphUri = "https://management.azure.com" + $AzScope.Id + "/providers/Microsoft.Authorization/roleAssignmentSchedules?api-version=2020-10-01"
                    $PIMAzResourceRoleAssignmentsRaw += ((invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers).Content)
                }

            $PIMAzResourceRoleAssignments = ($PIMAzResourceRoleAssignmentsRaw | ConvertFrom-Json).value.properties

        # Step 2/2 - Build array with better naming

            $PIMAzResourceRoleAssignmentsArray = @()
        
            ForEach ($Entry in $PIMAzResourceRoleAssignments)
                {
                    If ($Entry.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.StartDateTime -End $Entry.EndDateTime).TotalDays
                            $TimeSpanDays = [math]::Round($TimeSpanDays,0)
                            $SchedulePermanent    = "FALSE"
                        }
                    Else
                        {
                            $TimeSpanDays = "Permanent"
                            $SchedulePermanent    = "TRUE"
                        }

                    If ($Entry.RoleEligibilityScheduleRequestId)
                        {
                            $AssignmentType = "Eligible"
                        }
                    ElseIf ($Entry.RoleAssignmentScheduleRequestId)
                        {
                            $AssignmentType = "Assigned"
                        }

                        # Try fetching as user
                        $principal = $Global:Users_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                        If ($Principal -eq $null) {
                            # Try group
                            $principal = $Global:Groups_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                                If ($Principal -eq $null) {
                                    # Try service principal
                                    $principal = $Global:ServicePrincipals_All_ID | where-object { $_.Id -eq $Entry.PrincipalId }
                                }
                        }
                        $PrincipalDisplayName = $principal.DisplayName
                        
                        $RoleDefinitionId = $Entry.roleDefinitionId.Split('/')[-1]
                        $RoleDisplayName = ($Global:Role_Group_Definitions_ID | where-object { $_.Id -eq $RoleDefinitionId }).DisplayName
                        If ($RoleDisplayName -eq $null)
                            {
                                $RoleDisplayName = ($Global:AzureResourcesRole_Definitions_ID | where-object { $_.Id -eq $RoleDefinitionId }).Name
                            }

                    $Obj = new-object PSCustomObject
                    $Obj | Add-Member -MemberType NoteProperty -Name AssignmentType -Value $AssignmentType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedDateTime -Value $Entry.CreatedOn -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name CreatedUsing -Value $Entry.requestorId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ResourceScope -Value $Entry.Scope -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ResourceScopeDisplayName -Value $Entry.expandedProperties.scope.displayName -Force
                    If ($AssignmentType -eq "Assigned")
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.RoleAssignmentScheduleRequestId -Force
                        }
                    ElseIf ($AssignmentType -eq "Eligible")
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value $Entry.RoleEligibilityScheduleRequestId -Force
                        }
                    Else
                        {
                            $Obj | Add-Member -MemberType NoteProperty -Name Id -Value "" -Force
                        }
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $Entry.PrincipalId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalType -Value $Entry.PrincipalType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name PrincipalDisplayName -Value $PrincipalDisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleId -Value $RoleDefinitionId -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name RoleDisplayName -Value $RoleDisplayName -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Justification -Value $Entry.justification -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleStartDateTime -Value $Entry.StartDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationEndDateTime -Value $Entry.EndDateTime -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleExpirationType -Value $Entry.Expiration.Type -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name MemberType -Value $Entry.memberType -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleRecurrence -Value $Entry.Recurrence -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name ScheduleTimeSpanDays -Value $TimeSpanDays -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name SchedulePermanent -Value $SchedulePermanent -Force
                    $Obj | Add-Member -MemberType NoteProperty -Name Status -Value $Entry.Status -Force
                    $PIMAzResourceRoleAssignmentsArray += $Obj
                }


    #-----------------------------------------------------------------------------------------------------

    Write-host "[ 13 / $($MaxSteps) ] Getting all PIM Role Assignments in PIM for Groups .... Please Wait !"

    $Global:Groups_All_ID_Scoped = $Global:Groups_All_ID | Where-Object { $_.DisplayName -like "PIM-*" } | Sort-Object -Property DisplayName

        # Step 1/2 - Get raw data

            $PIMGroupEligible = @()
            $PIMGroupActive  = @()

            Foreach ($Group in $Global:Groups_All_ID_Scoped)
                {
                    Write-host ""
                    Write-host "Getting PIM for Group Eligible Assignments for group $($Group.DisplayName) ... Please Wait !"

                    $PIMGroupEligible  += Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($Group.Id)'" -ExpandProperty *

                    Write-host "Getting PIM for Group Active Assignments for group $($Group.DisplayName) ... Please Wait !"

                    $PIMGroupActive += Get-MgIdentityGovernancePrivilegedAccessGroupAssignmentSchedule -Filter "groupId eq '$($Group.Id)'" -ExpandProperty *
                }

        # Step 2/2 - Build array with better naming

            $PIMGroupArray = @()
        
            ForEach ($Entry in $PIMGroupEligible)
                {
                    If ($Entry.ScheduleInfo.Expiration.EndDateTime)
                        {
                            $TimeSpanDays = (New-TimeSpan -start $Entry.ScheduleInfo.StartDateTime -End $Entry.ScheduleInfo.Expiration.EndDateTime).TotalDays
                            $TimeSpanDays = [int][math]::Round($TimeSpanDays,0)
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
                            $TimeSpanDays = [int][math]::Round($TimeSpanDays,0)
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

    #-----------------------------------------------------------------------------------------------------

    Write-host "[ 14 / $($MaxSteps) ] Building list of all permanent assignments in Azure (using Azure Resource Graph) ... Please Wait !"
    $Query = @"
    authorizationResources
    | where type == 'microsoft.authorization/roleassignments'
    | extend prop = properties
    | extend roleDefinitionIdFull = tostring(properties.roleDefinitionId)
    | extend roleDefinitionIdsplit = split(roleDefinitionIdFull,'/')
    | extend roleDefinitionId = tostring(roleDefinitionIdsplit[(4)])
    | extend roleAssignmentPrincipalType = properties.principalType
    | extend roleAssignmentDescription = properties.description
    | extend roleAssignmentPrincipalId = properties.principalId
    | extend roleAssignmentCreatedOn = properties.createdOn
    | extend roleAssignmentUpdatedOn = properties.updatedOn
    | extend roleAssignmentUpdatedById = properties.updatedBy
    | extend roleAssignmentCreatedById = properties.createdBy
    | extend roleAssignmentScope = properties.scope
    | project-away managedBy,kind,sku,plan,tags,identity,zones,location,resourceGroup,subscriptionId, extendedLocation,tenantId
    | join kind=leftouter (authorizationResources
            | where type == 'microsoft.authorization/roledefinitions'
            | extend roleDefinitionIdFull = tostring(id)
            | extend roleDefinitionIdsplit = split(roleDefinitionIdFull,'/')
            | extend roleDefinitionId = tostring(roleDefinitionIdsplit[(4)])
            | extend description = properties.description
            | extend roleName = properties.roleName
            | extend roleType = properties.type
            | project-away managedBy,kind,sku,plan,tags,identity,zones,location,resourceGroup,subscriptionId, extendedLocation,tenantId)
        on roleDefinitionId
    | project roleDefinitionId,roleName,roleType,roleAssignmentPrincipalType,roleAssignmentPrincipalId,roleAssignmentCreatedOn,roleAssignmentUpdatedOn,roleAssignmentUpdatedById,roleAssignmentCreatedById,roleAssignmentScope, prop
    | where (roleAssignmentPrincipalType == "User") or (roleAssignmentPrincipalType == "Group")
"@

    $PermanentRoleAssignments = $Query | Query-AzResourceGraph -QueryScope Tenant
    $PermanentRoleAssignments_Scoped = $PermanentRoleAssignments | Where-Object { ($_.RoleAssignmentPrincipalType -eq "User") -or ($_.RoleAssignmentPrincipalType -eq "Group") }


    # Correlate data - Azure Resources (permanent)
    $PermAzResourceRoleAssignmentsArray = @()
        ForEach ($Entry in $PermanentRoleAssignments_Scoped)
            {
                $Scope = $Entry.RoleAssignmentScope
                $PrincipalId = $Entry.roleAssignmentPrincipalId
                $PrincipalType = $Entry.roleAssignmentPrincipalType

                If ($Entry.roleAssignmentPrincipalType -eq "User")
                    {
                        $PrincipalName = ($Users_All_ID | Where-Object { $_.id -eq $Entry.roleAssignmentPrincipalId }).DisplayName
                        $PrincipalUPN = ($Users_All_ID | Where-Object { $_.id -eq $Entry.roleAssignmentPrincipalId }).UserPrincipalName
                    }
                ElseIf ($Entry.roleAssignmentPrincipalType -eq "Group")
                    {
                        $PrincipalName = ($Groups_All_ID | Where-Object { $_.id -eq $Entry.roleAssignmentPrincipalId }).DisplayName
                        $PrincipalUPN = ""
                    }
 
                $RoleId = $Entry.roleDefinitionId
                $RoleName = $Entry.RoleName

                Write-Output "    Processing role $($RoleName) for identity $($PrincipalName)"
             
                #New PSObject
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name Scope -value $Scope
                $obj | Add-Member -MemberType NoteProperty -Name RoleId -value $RoleId
                $obj | Add-Member -MemberType NoteProperty -Name RoleName -value $RoleName
                $obj | Add-Member -MemberType NoteProperty -Name PrincipalId -Value $PrincipalId
                $obj | Add-Member -MemberType NoteProperty -Name PrincipalName -Value $PrincipalName
                $obj | Add-Member -MemberType NoteProperty -Name PrincipalUPN -Value $PrincipalUPN
                $obj | Add-Member -MemberType NoteProperty -Name PrincipalType -Value $PrincipalType
             
                $PermAzResourceRoleAssignmentsArray += $obj
            }



##########################################################################################################################
# Main Program
##########################################################################################################################

    $FileOutputPath = Get-PimOutputDir
    MD $FileOutputPath -ErrorAction SilentlyContinue | Out-Null

    $FileOutputPIM4Groups = $FileOutputPath + "\" + "PIM-Delegations-PIM4Groups.csv"
    $FileOutputEntraIDRoles = $FileOutputPath + "\" + "PIM-Delegations-EntraID-Roles.csv"
    $FileOutputAzureRoles = $FileOutputPath + "\" + "PIM-Delegations-Azure-Roles.csv"

    Remove-Item $FileOutputPIM4Groups -ErrorAction SilentlyContinue
    Remove-Item $FileOutputEntraIDRoles -ErrorAction SilentlyContinue
    Remove-Item $FileOutputAzureRoles -ErrorAction SilentlyContinue


#############################################
# Entra ID Role Assignments
#############################################

    $TableName      = "Entra_Id_Role_Assignments"
    $TableSelection = $PIMRolesArray | where-Object { (!([string]::IsNullOrEmpty($_.CreatedUsing))) } | 
                                                Select-Object AssignmentType, `
                                                                RoleDisplayName, `
                                                                PrincipalDisplayName, `
                                                                DirectoryScope, `
                                                                ScheduleTimeSpanDays, `
                                                                SchedulePermanent, `
                                                                ScheduleStartDateTime, `
                                                                ScheduleExpirationEndDateTime, `
                                                                RoleId,`
                                                                DirectoryScopeId, `
                                                                PrincipalId, `
                                                                ScheduleExpirationType, `
                                                                CreatedUsing, `
                                                                CreatedDateTime` | 
                                                Sort-Object -Property PrincipalDisplayName, DirectoryScope, RoleDisplayName

    If ($TableSelection)
        {
            Write-Output "Exporting $($TableName) .... Please Wait !"
            $TableSelection | Export-csv -Path $FileOutputEntraIDRoles -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation
        }


#############################################
# Azure Resource Assignments (PIM)
#############################################

    $Provisioned_PIMAzResourceRoleAssignmentsArray = $PIMAzResourceRoleAssignmentsArray | where-Object { ("Provisioned" -in $_.Status) -and ("Inherited" -ne $_.memberType) } | Sort-Object -Property AssignmentType, ResourceScopeDisplayName, RoleId, ResourceScope, PrincipalId -Unique
   
    $TableName      = "Azure_Resource_Assignments_PIM"
    $TableSelection = $Provisioned_PIMAzResourceRoleAssignmentsArray | 
                                                          Select-Object AssignmentType, `
                                                                        ResourceScopeDisplayName, `
                                                                        RoleDisplayName, `
                                                                        PrincipalType, `
                                                                        PrincipalDisplayName, `
                                                                        ScheduleTimeSpanDays, `
                                                                        SchedulePermanent, `
                                                                        ScheduleStartDateTime, `
                                                                        ScheduleExpirationEndDateTime, `
                                                                        MemberType,
                                                                        RoleId,`
                                                                        ResourceScope, `
                                                                        PrincipalId, `
                                                                        Id, `
                                                                        ScheduleExpirationType, `
                                                                        CreatedDateTime, ` 
                                                                        CreatedUsing | `
                                                        Sort-Object -Property ResourceScopeDisplayName, RoleDisplayName
    If ($TableSelection)
        {
            Write-Output "Exporting $($TableName) .... Please Wait !"
            $TableSelection | Export-csv -Path $FileOutputAzureRoles -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation
        }

#############################################
# PIM for Groups Assignments
#############################################

    $TableName      = "PIM_for_Groups"
    $TableSelection = $PIMGroupArray | `
                                        Select-Object AssignmentType, `
                                                    PrincipalDisplayName, `
                                                    GroupDisplayName, `
                                                    ScheduleTimeSpanDays, `
                                                    SchedulePermanent, `
                                                    ScheduleStartDateTime, `
                                                    ScheduleExpirationEndDateTime, `
                                                    AccessId, `
                                                    GroupId,`
                                                    Id, `
                                                    PrincipalId, `
                                                    ScheduleExpirationType, `
                                                    CreatedDateTime, ` 
                                                    CreatedUsing | `
                                        Sort-Object -Property PrincipalDisplayName, GroupDisplayName
    If ($TableSelection)
        {
            Write-Output "Exporting $($TableName) .... Please Wait !"
            $TableSelection | Export-csv -Path $FileOutputPIM4Groups -Force -Encoding UTF8 -Delimiter ";" -NoTypeInformation
        }
