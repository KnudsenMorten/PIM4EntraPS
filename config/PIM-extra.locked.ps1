#----------------------------------------------------------------------------------------

# Goal: Detect Eligible Role Assignment, not defined in data - for clean-up purpose
<#
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

#>
