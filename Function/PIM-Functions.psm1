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
            return ( New-Object PSCredential -ArgumentList @(
                                    "$($Domain)\$($GMSAName)",
                                    (ConvertTo-SecureString $stringBuilder.ToString() -AsPlainText -Force)
                                    ))
        }
    }
}

Function Add-Exchange-Role-to-PAG-Group
{
   [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$RoleName,
            [Parameter(mandatory)]
                [string]$GroupTag
         )

    $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }
            
    If ($Group)
        {
            $GroupName = $Group.GroupName
            Add-RoleGroupMember "$($RoleName)" -Member $GroupName
        }
    Else
        {
            Write-host "ERROR: Could NOT find any PAG groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
        }

}

Function Assign-User-PIM-PAG-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [Object]$UserInfo,
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [array]$GroupAllArray,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                [string]$AssignmentType
         )

    #####################################
    # Add User to PIM Group
    #####################################

<#
    $UserInfo = $UserInfo
    $GroupArray = $GroupArray
    $GroupAllArray = $EntraID_Groups
    $AssignmentType = $AssignmentType
    $NumOfDaysWhenExpire = $NumOfDaysWhenExpire
    $Permanent = $Permanent
#>

#    $GroupList = $GroupArray.split(",")

    $UserId = $UserInfo.UserPrincipalName

    $GroupInfo = $GroupAllArray | Where-Object { $_.DisplayName -eq $GroupName }

    If ($GroupInfo)
        {
            Import-Module Microsoft.Graph.DeviceManagement.Enrollment

            # Check if group already exist
            # $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'"

            $Justification = "IAC: Assigning access to group $($GroupName) for user $($UserId)"

                $params = @{
	                accessId = "member"
	                groupId = $GroupInfo.Id
	                action = "AdminAssign"
	                justification = $Justification
	                directoryScopeId = "/"
                    principalId = $UserInfo.Id
                }

                If (!($Permanent))
                    {
                        $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                        $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                        $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                            $params += @{
	                                        scheduleInfo = @{
		                                                        startDateTime = $startDateTime
		                                                        expiration = @{
			                                                                    type = "AfterDateTime"
			                                                                    endDateTime = $endDateTime
		                                                        }
                                                            }
                                        }
                    }


                    ElseIf ($Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                            type = "noExpiration"
		                                                                            }
                                                                }
                                            }
                        }


                If ($AssignmentType -eq "Eligible")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning Admin $($Userid) as Eligible"
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try
                            {
                                New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -ErrorAction SilentlyContinue
                            }
                        Catch
                            {
                            }
                    }
                ElseIf ($AssignmentType -eq "Active")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning Admin $($Userid) as Active "
                        Write-host "      to group $($GroupInfo.DisplayName)"

                        Try
                            {
                                New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction SilentlyContinue
                            }
                        Catch
                            {
                            }
                    }
        }
}


Function Create-AdministrativeUnit
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$DisplayName,
            [Parameter(mandatory)]
                [string]$Description,
            [Parameter()]
                [ValidateSet("HiddenMembership", "Public")]
                $Visibility = "Public",
            [Parameter()]
                [ValidateSet("Authentication Administrator", "Cloud Device Administrator","Groups Administrator","Helpdesk Administrator","License Administrator","Password Administrator","Printer Administrator","SharePoint Administrator","Teams Administrator","Teams Devices Administrator","User Administrator")]
                [string]$RoleAssignment = $null
         )


    Import-Module Microsoft.Graph.Identity.DirectoryManagement

    $params = @{
	              displayName = $DisplayName
	              description = $Description
	              visibility  = $Visibility
               }

        $Au = Get-MgDirectoryAdministrativeUnit -All:$true
        $Au = $AU | Where-Object { $_.DisplayName -eq $DisplayName }
        If ($Au)
            {
                write-host ""
                Write-host "Updating Administrative Unit (AU) $($DisplayName)"
                $Au = Update-MgDirectoryAdministrativeUnit -AdministrativeUnitId $AU.id -BodyParameter $params
            }
        Else
            {
                write-host ""
                Write-host "Creating Administrative Unit (AU) $($DisplayName)"
                $Au = New-MgDirectoryAdministrativeUnit  -BodyParameter $params
            }
}


Function Add-AdministrativeUnit-Member
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$AuId,
            [Parameter(mandatory)]
                [string]$ObjectId,
            [Parameter()]
                [ValidateSet("Group", "User")]
                $AddType
         )

    Import-Module Microsoft.Graph.Identity.DirectoryManagement

    If ($AddType -eq "Group")
        {
            $params = @{
	                     "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$($ObjectId)"
                       }
        }
    If ($AddType -eq "User")
        {
            $params = @{
	                     "@odata.id" = "https://graph.microsoft.com/v1.0/user/$($ObjectId)"
                       }
        }

    Import-Module Microsoft.Graph.Identity.DirectoryManagement

    $Members = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $AuId
    If ($ObjectId -in $Members.id)
        {
            Write-host "Member is already present ... skipping !"
        }
    Else
        {
            Write-host "Adding [$($AddType)] with $($ObjectId) to Administrative Unit (AU) with id $($AuId)"
            $Result = New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $AuId -BodyParameter $params
        }
}



Function Create-PIM-Group-Role
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$RoleDefinitionName,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                $AssignmentType
         )

<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = $Role_GroupName
    $GroupDescription    = $Role_GroupDescription
    $RoleDefinitionName  = $RoleDefinitionName
    $NumOfDaysWhenExpire = 365
    $AssignmentType      = "Eligible"
    $Permanent           = $false

    $GroupName           = $TargetSelected
    $RoleDefinitionName  = $RoleSelected
    $AssignmentType      = $Assignment_Type
    $NumOfDaysWhenExpire = $Assignment_NumOfDaysWhenExpire
    $Permanent           = $Assignment_Permanent
#>

    Import-Module Microsoft.Graph.Groups

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
    
    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $true
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName.Substring(0,64)
                    }
                }
            Else
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $true
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName
                    }
                }

            Write-Host ""
            Write-Host "Creating role group $($GroupName)"
            $Result = New-MgGroup -BodyParameter $params -ErrorAction SilentlyContinue
            
            # Waiting to let it sync
            Start-Sleep -Seconds 3
            $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -ErrorAction SilentlyContinue
        }

    If ($Group)
        {
            Import-Module Microsoft.Graph.DeviceManagement.Enrollment

            # Search for RoleDefinition in array list of Role Definitions
            $roleDefinition = $Global:Role_Group_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
            $roleDefinitionId = $roleDefinition.Id

            # Get Id of new group created
            $principalId = $Group.Id

            $Justification = "IAC: Assigning role $($RoleDefinitionName) to role group $($Group.DisplayName)"

            If ($roleDefinitionId)
                {
                    $params = @{
	                             action = "AdminAssign"
	                             justification = $Justification
	                             directoryScopeId = "/"
                                 roleDefinitionId = $roleDefinitionId
                                 principalId = $principalId
                               }

                    If (!($Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
		                                                            startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                        type = "AfterDateTime"
			                                                                        endDateTime = $endDateTime
		                                                            }
                                                                }
                                            }
                        }


                    ElseIf ($Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                            type = "noExpiration"
		                                                                            }
                                                                }
                                            }
                        }
                    
                    If ($AssignmentType -eq "Eligible")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as eligible"
                            Write-host "      for role $($GroupName)"

                            New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
<#
                            $BodyJson = $params | ConvertTo-Json -Depth 20
                            $Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
                            $result = Invoke-MgGraphRequestPS -Uri $Uri -Method POST -OutputType PSObject -Body $BodyJson
#>
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleDefinitionName) role as active"
                            write-host "      for role $($GroupName)"
                            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
                        }
                }
        }
}


Function Assign-PIM-Group-Resource
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$AzScope,
            [Parameter(mandatory)]
                [string]$AzScopePermission,
            [Parameter(mandatory)]
                [array]$ResourceInfoArray,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                $AssignmentType
         )

    Import-Module Microsoft.Graph.Groups

<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = "PAG-Role-PlatformOps-L3-Admin-ID"
    $NumOfDaysWhenExpire = 365
    $AssignmentType      = "Eligible"
    $Permanent           = $false

    $AzScope             = "/providers/Microsoft.Management/managementGroups/00000000-0000-0000-0000-000000000000"
    $AzScopePermission   = "Owner"
#>

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue
    
    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $false
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName.Substring(0,64)
                    }
                }
            Else
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $false
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName
                    }
                }

            Write-Host ""
            Write-Host "Creating Resource Group $($GroupName)"
            $Result = New-MgGroup -BodyParameter $params -Erroraction SilentlyContinue
            $Group = Get-MgGroup -GroupId $Result.Id -Erroraction SilentlyContinue
        }

    If ($Group)
        {
            Import-Module Microsoft.Graph.DeviceManagement.Enrollment

            # Search for AzScopePermission in array list of Role Definitions
            $roleDefinition = Get-AzRoleDefinition $AzScopePermission -Erroraction SilentlyContinue

            $roleDefinitionId = $AzScope + "/providers/Microsoft.Authorization/roleDefinitions/" + $roleDefinition.Id

            # Get Id of new group created
            $principalId = $Group.Id

            $Justification = "IAC: Assigning role $($AzScopePermission) to group $($Group.DisplayName)"

            If (!($Permanent))
                {
                    $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                    $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                    $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                    $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                properties = @{
                                                                    principalId = $principalId
                                                                    roleDefinitionId = $roleDefinitionId
	                                                                requestType = "AdminAssign"
                                                                    justification = $Justification
                                                                    scheduleInfo = @{
                                                                                    startDateTime = $startDateTime
                                                                                    expiration = @{
			                                                                                            type = "AfterDateTime"
			                                                                                            endDateTime = $endDateTime
                                                                                                    }
                                                                                }
                                                                }
                                            }
                }
            ElseIf ($Permanent)
                {
                    $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                    $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                    $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                    $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                properties = @{
                                                                    principalId = $principalId
                                                                    roleDefinitionId = $roleDefinitionId
                                                                    justification = $Justification
	                                                                requestType = "AdminAssign"
                                                                    scheduleInfo = @{
                                                                                        startDateTime = $startDateTime
                                                                                        expiration = @{
			                                                                                                type = "noExpiration"
                                                                                                      }
                                                                                    }
                                                              }
                                            }
                }

            $Headers = Get-AzAccessTokenManagement

            $Guid = (new-guid).Guid

            $AzRoleAssignmentBodyJson = $AzRoleAssignmentBody | ConvertTo-Json -Depth 20

            $AzDisplayName = ($ResourceInfoArray | Where-Object { $_.Id -eq $AzScope }).DisplayName
            If ($AssignmentType -eq "Eligible")
                {
                    Write-Host ""
                    Write-Host "PIM - Assigning $($AzScopePermission) role as eligible"
                    Write-host "      for resource group $($GroupName)"
                    Write-Host "      on scope [ $($AzDisplayName) ]"
                    Write-host "      $($AzScope) "

                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                    Try
                        {
                            $Response   = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                        }
                    Catch
                        {
                        }
                }
            ElseIf ($AssignmentType -eq "Active")
                {
                    Write-Host ""
                    Write-Host "PIM - Assigning $($AzScopePermission) role as active"
                    Write-host "      for resource group $($GroupName)"
                    Write-Host "      on scope [ $($AzDisplayName) ]"
                    Write-host "      $($AzScope) "

                    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                    Try
                        {
                            $Response   = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                        }
                    Catch
                        {
                        }
                }
        }
}


Function CreateUpdate-PIM-PAG-Group
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$GroupDescription,
            [Parameter(mandatory)]
                [string]$IsRoleAssignable = "FALSE"

         )


<#  TROUBLESHOOTING
    $GroupName = $ScopedAdminL3ResourceServerPermissionGroupName_ID
    $GroupDescription = $GroupDescription
    $IsRoleAssignable = $IsRoleAssignable
#>
    
    If ($IsRoleAssignable -eq "FALSE")
        {
            $IsRoleAssignable = $FALSE
        }
    ElseIf ($IsRoleAssignable -eq "TRUE")
        {
            $IsRoleAssignable = $TRUE
        }
    Else
        {
            $IsRoleAssignable = $FALSE
        }

    Import-Module Microsoft.Graph.Groups

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue
    
    If (!($Group))   # create group if it doesn't exist !
        {
            If ($GroupName.Length -ge 64)
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $IsRoleAssignable
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName.Substring(0,64)
                    }
                }
            Else
                {
                    $params = @{
	                    description = $GroupDescription
	                    displayName = $GroupName
	                    groupTypes = @(
	                    )
	                    isAssignableToRole = $IsRoleAssignable
	                    mailEnabled = $false
	                    securityEnabled = $true
                        mailNickname = $GroupName
                    }
                }

            Write-Host ""
            Write-Host "Creating privileged access group $($GroupName)"
            $Result = New-MgGroup -BodyParameter $params -Erroraction SilentlyContinue
            $Group = Get-MgGroup -GroupId $Result.Id -Erroraction SilentlyContinue
        }
    Else
        {
            $params = @{
	            description = $GroupDescription
	            displayName = $GroupName
	            groupTypes = @(
	            )
	            isAssignableToRole = $true
	            mailEnabled = $false
	            securityEnabled = $true
                mailNickname = $GroupName
            }

            Write-Host ""
            Write-Host "Updating group $($GroupName)"
            $Result = Update-MgGroup -GroupId $Group.Id -BodyParameter $params -Erroraction SilentlyContinue
        }
}


Function Create-PIM-PAG-Assignment
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$PAG_GroupName,
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter()]
                [boolean]$Permanent,
            [Parameter()]
                [int]$NumOfDaysWhenExpire,
            [Parameter(mandatory)]
                [ValidateSet("Eligible", "Active")]
                [string]$AssignmentType
         )

<#
    TROUBLESHOOTING ONLY !!

            $GroupName            = "DREG-AzRes-Platform-Management-Global-Sentinel-LogAnalytics-Reader-MP-T1-ID"
            $PAG_GroupName        = "PAG-Role-SecOps-L2-Operator-ID"
            $AssignmentType       = "Active"
            $NumOfDaysWhenExpire  = 180
            $Permanent            = $false
#>

    # Check if group already exist
    $Group = Get-MgGroup -Filter "DisplayName eq '$($Groupname)'" -Erroraction SilentlyContinue

    # Check if group already exist
    $PAGGroup = Get-MgGroup -Filter "DisplayName eq '$($PAG_GroupName)'" -Erroraction SilentlyContinue


    If ( ($Group) -and ($PAGGroup) )
        {
            Import-Module Microsoft.Graph.DeviceManagement.Enrollment

            $Justification = "IAC: Assigning access to group $($GroupName) for PAG group $($PAG_GroupName)"

                $params = @{
	                accessId = "member"
	                groupId = $Group.Id
	                action = "AdminAssign"
	                justification = $Justification
	                directoryScopeId = "/"
                    principalId = $PAGGroup.Id
                }

                If (!($Permanent))
                    {
                        $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                        $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                        $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                            $params += @{
	                                        scheduleInfo = @{
		                                                        startDateTime = $startDateTime
		                                                        expiration = @{
			                                                                    type = "AfterDateTime"
			                                                                    endDateTime = $endDateTime
		                                                        }
                                                            }
                                        }
                    }


                    ElseIf ($Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                                $params += @{
	                                            scheduleInfo = @{
   	                                                                startDateTime = $startDateTime
		                                                            expiration = @{
			                                                                         type = "noExpiration"
		                                                                          }
                                                                }
                                            }
                        }

                 Import-Module Microsoft.Graph.Beta.Identity.Governance

                If ($AssignmentType -eq "Eligible")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning PAG $($PAG_GroupName) as Eligible "
                        Write-host "      to group $($Groupname)"

                        $Result = New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params -Erroraction SilentlyContinue
                    }
                ElseIf ($AssignmentType -eq "Active")
                    {
                        Write-Host ""
                        Write-Host "PIM - Assigning PAG $($PAG_GroupName) as Active to group $($Groupname)"

                        $Result = New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -Erroraction SilentlyContinue
                    }
        }
}


Function Update-PIM-Policy-Resource
{

    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [ValidateSet("RoleManagementPolicyEnablementRule","RoleManagementPolicyExpirationRule","RoleManagementPolicyNotificationRule")]
                $RuleType,
            [Parameter(mandatory)]
                [ValidateSet("Assignment","Eligibility")]
                $AssignmentType,
            [Parameter(mandatory)]
                [string]$RuleId,
            [Parameter()]
                [ValidateSet("Admin_EndUser_Assignment","Admin_Admin_Eligibility","Requestor_EndUser_Assignment","Requestor_Admin_Eligibility")]
                $NotificationType,
            [Parameter()]
                [ValidateSet("Admin_Assignment","Admin_Eligibility","EndUser_Assignment")]
                $enabledRules,
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_EndUser_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


    $Headers = Get-AzAccessTokenManagement

    Write-host "  Processing PIM policy $($ruleId)"
    $Guid = (new-guid).Guid

    If ($RuleType -eq "RoleManagementPolicyExpirationRule")
        {
            $PolicyBody = [pscustomobject][ordered]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired
                                                    maximumDuration = $Expiration_EndUser_Assignment_maximumDuration
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                }
                                            )
                             }
            }
        }

    #---------------------------------------------------------------------------------------------------------------------

    If ($RuleType -eq "RoleManagementPolicyEnablementRule")
        {
            $PolicyBody = [PSCustomObject]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                }
                                            )
                             }
            }

            #-------------------------------------------
            If ($enabledRules -eq "Admin_Assignment")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                }
            #-------------------------------------------
            If ($enabledRules -eq "Admin_Eligibility")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_Admin_Eligibility_enabledRules}
                }
            #-------------------------------------------
            If ($enabledRules -eq "EndUser_Assignment")
                {
                    $PolicyBody.properties.rules += @{enabledRules = $Enablement_EndUser_Assignment_enabledRules}
                }
            #-------------------------------------------
            If ($AssignmentType -eq "Eligibility")
                {
                    $PolicyBody.properties.rules += @{isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired}
                    $PolicyBody.properties.rules += @{maximumDuration = $Expiration_EndUser_Assignment_maximumDuration}
                }
            #-------------------------------------------
        }

    #---------------------------------------------------------------------------------------------------------------------

    If ($RuleType -eq "RoleManagementPolicyNotificationRule")
        {
            $PolicyBody = [pscustomobject][ordered]@{
                properties = @{
                                    rules = @(
                                                @{
                                                    id = $ruleId
                                                    ruleType = "$($RoleType)"
                                                    target = @{
                                                                caller = "Admin"
                                                                operations = @(
			                                                                    "All"
                                                                                )
                                                                }
                                                    level = "$AssignmentType)"
                                                    targetObjects = $null
                                                    inheritableSettings = $null
                                                    enforcedSettings = $null
                                                 }
                                             )
                              }
            }
        }

        #-------------------------------------------------

        If ($NotificationType -eq "Admin_EndUser_Assignment")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Admin_EndUser_Assignment_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Admin_EndUser_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Admin_EndUser_notificationLevel}
                $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Admin_EndUser_notificationRecipients}
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Admin_Admin_Eligibility")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Admin_Admin_Eligibility_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Admin_Admin_Eligibility_recipientType_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel}
                $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients}
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Requestor_EndUser_Assignment")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Requestor_EndUser_Assignment_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Requestor_EndUser_Assignment_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel}
                $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients}
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

        If ($NotificationType -eq "Requestor_Admin_Eligibility")
            {
                $PolicyBody.properties.rules += @{notificationType = $Notification_Requestor_Admin_Eligibility_notificationType}
                $PolicyBody.properties.rules += @{recipientType = $Notification_Requestor_Admin_Eligibility_recipientType}
                $PolicyBody.properties.rules += @{notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel}
                $PolicyBody.properties.rules += @{notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients}
                $PolicyBody.properties.rules += @{isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

    $PolicyBodyJson = $PolicyBody | ConvertTo-Json -Depth 20

    $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
    $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $PolicyBodyJson
}


Function Update-PIM-Policy-Role
{

    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [ValidateSet("PolicyEnablementRule","PolicyExpirationRule","PolicyAuthenticationContextRule","PolicyNotificationRule","PolicyApprovalRule")]
                $RuleType,
            [Parameter(mandatory)]
                [string]$PolicyId,
            [Parameter(mandatory)]
                [string]$RuleId,
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_EndUser_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


    Write-host "Processing PIM policy $($RuleId)"
    $Guid = (new-guid).Guid

    # Baseline policy for Roles
    $odataType = "#microsoft.graph.unifiedRoleManagement" + $RuleType
    $PolicyBody = @{
        '@odata.type' = $odataType
        id = $ruleId
        target = @{
                    '@odata.type' = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
                    operations = @(
			                        "All"
                                  )
                  }
        inheritableSettings = $null
        enforcedSettings = $null
    }

    #---------------------------------------------------------------------------------------------------------------------

    # Expiration
        If ($RuleId -eq "Expiration_EndUser_Assignment")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_EndUser_Assignment_maximumDuration}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "EndUser"}
            }
        If ($RuleId -eq "Expiration_Admin_Eligibility")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_Admin_Eligibility_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_Admin_Eligibility_maximumDuration}
                $PolicyBody.target += @{level = "Eligbility"}
                $PolicyBody.target += @{caller = "Admin"}
            }
        If ($RuleId -eq "Expiration_Admin_Assignment")
            {
                $PolicyBody += @{isExpirationRequired = $Expiration_Admin_Assignment_isExpirationRequired}
                $PolicyBody += @{maximumDuration = $Expiration_Admin_Assignment_maximumDuration}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "Admin"}
            }

    # Activation
        If ($RuleId -eq "Enablement_EndUser_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_EndUser_Assignment_enabledRules}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "EndUser"}
            }
        If ($RuleId -eq "Enablement_Admin_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                $PolicyBody.target += @{level = "Assignment"}
                $PolicyBody.target += @{caller = "Admin"}
            }
<#
        If ($RuleId -eq "AuthenticationContext_EndUser_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_Admin_Assignment_enabledRules}
                $PolicyBody += @{level = "Assignment"}
                $PolicyBody += @{caller = "EndUser"}
            }
#>

    # Approval
<#
        If ($RuleId -eq "Approval_EndUser_Assignment")
            {
                $PolicyBody += @{enabledRules = $Enablement_Admin_Eligibility_enabledRules}
                $PolicyBody += @{level = "Assignment"}
                $PolicyBody += @{caller = "EndUser"}
            }
#>

    # Notification
        If ($RuleId -eq "Notification_Admin_EndUser_Assignment")
            {
                $PolicyBody += @{notificationType = $Notification_Admin_EndUser_Assignment_notificationType}
                $PolicyBody += @{recipientType = $Notification_Admin_EndUser_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Admin_EndUser_notificationLevel}
                $PolicyBody += @{notificationRecipients = $Notification_Admin_EndUser_notificationRecipients}
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Admin_Admin_Eligibility")
            {
                $PolicyBody += @{notificationType = $Notification_Admin_Admin_Eligibility_notificationType}
                $PolicyBody += @{recipientType = $Notification_Admin_Admin_Eligibility_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel}
                $PolicyBody += @{notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients}
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Requestor_EndUser_Assignment")
            {
                $PolicyBody += @{notificationType = $Notification_Requestor_EndUser_Assignment_notificationType}
                $PolicyBody += @{recipientType = $Notification_Requestor_EndUser_Assignment_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel}
                $PolicyBody += @{notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients}
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled}
            }
        If ($RuleId -eq "Notification_Requestor_Admin_Eligibility")
            {
                $PolicyBody += @{notificationType = $Notification_Requestor_Admin_Eligibility_notificationType}
                $PolicyBody += @{recipientType = $Notification_Requestor_Admin_Eligibility_recipientType}
                $PolicyBody += @{notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel}
                $PolicyBody += @{notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients}
                $PolicyBody += @{isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled}
            }

        #-------------------------------------------------

    # Update policy
        Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $PolicyId `
                                                -UnifiedRoleManagementPolicyRuleId $RuleId `
                                                -BodyParameter $PolicyBody
}


######################################################################################################
# DROG | PIM for Role Groups | Creation & Delegation
######################################################################################################

<#  DISBALED to assign Roles directly to PAG groups - due to missing nesting support

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Role Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $EntraID_Role_Data = Import-csv -Path $EntraID_Roles_DataFile -Delimiter ";" -Encoding UTF8


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # create Role Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        ForEach ($Entry in $EntraID_Role_Data)
            {
                $GroupName           = $Entry.GroupName
                $GroupDescription    = $Entry.GroupDescription
                $AdministrativeUnit  = $Entry.AdministrativeUnit
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

                Create-PIM-Group-Role -GroupName $GroupName `
                                        -RoleDefinitionName $RoleDefinitionName `
                                        -AssignmentType $AssignmentType `
                                        -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                        -Permanent:$Permanent

                    
                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
                $AU = Get-MgDirectoryAdministrativeUnit -All:$true
                $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
                Add-AdministrativeUnit-Member -AuId $AU.Id -AddType Group -ObjectId $GroupInfo.Id
            }
#>


######################################################################################################
# DREG | PIM for Azure Resources | Resource Groups | Creation & Delegation
######################################################################################################
<#
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Resource Groups - contains directory role assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $Azure_Resources_Data = Import-csv -Path $Azure_Resources_DataFile -Delimiter ";" -Encoding UTF8

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # create resource groups - contains resource assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        ForEach ($Entry in $Azure_Resources_Data)
            {
                $GroupName           = $Entry.GroupName
                $GroupDescription    = $Entry.GroupDescription
                $AdministrativeUnit  = $Entry.AdministrativeUnit
                $AzScope             = $Entry.AzScope
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

                Assign-PIM-Group-Resource -GroupName $GroupName `
                                            -AzScope $AzScope `
                                            -AzScopePermission $AzScopePermission `
                                            -AssignmentType $AssignmentType `
                                            -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                            -Permanent:$Permanent

                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
                $AU = Get-MgDirectoryAdministrativeUnit -All:$true
                $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
                    
                $GroupInfo = Get-MgGroup -Filter "DisplayName eq '$($GroupName)'"
                Add-AdministrativeUnit-Member -AuId $AU.Id -AddType Group -ObjectId $GroupInfo.Id
            }
#>



Function CreateUpdate-PIM-for-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$DeptGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$RoleGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$TaskGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ServiceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ProcessGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ResourceGroupsDefinitionFile
         )

######################################################################################################
# PAG | PIM for Groups | Privileged Access Group (PAG) - Creation
######################################################################################################

<#
    $DeptGroupsDefinitionFile = $DeptGroupsDefinitionFile
    $RoleGroupsDefinitionFile = $RoleGroupsDefinitionFile
    $TaskGroupsDefinitionFile = $TaskGroupsDefinitionFile
    $ServiceGroupsDefinitionFile = $ServiceGroupsDefinitionFile
    $ProcessGroupsDefinitionFile = $ProcessGroupsDefinitionFile
    $ResourceGroupsDefinitionFile = $ResourceGroupsDefinitionFile
#>

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Scope Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Import-csv -Path $DeptGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $RoleGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $TaskGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ProcessGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ServiceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ResourceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create AUs for Privileged Access Groups (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
<#
        $AUs = $PAG_Groups_Data | select-object -property AdministrativeUnit -unique

        ForEach ($AU in $AUs)
            {
                $AdministrativeUnit = $AU.AdministrativeUnit
                Create-AdministrativeUnit -DisplayName $AdministrativeUnit -Description $AdministrativeUnit -Visibility Public
            }
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true
#>

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Create Privileged Access Group (PAG)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # Build list of all Administrative Units
        $AU_ALL = Get-MgDirectoryAdministrativeUnit -All:$true

        ForEach ($Entry in $PAG_Groups_Data)
            {
                $GroupName             = $Entry.GroupName
                $GroupDescription      = $Entry.GroupDescription
                $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
                $IsRoleAssignable      = $Entry.IsRoleAssignable

                write-host ""
                Write-host "Processing PAG group $($GroupName)"
                CreateUpdate-PIM-PAG-Group -GroupName $GroupName `
                                           -GroupDescription $GroupDescription `
                                           -IsRoleAssignable $IsRoleAssignable

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
}


Function Build-List-of-Definitions
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$DeptGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$RoleGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$TaskGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ServiceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ProcessGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$ResourceGroupsDefinitionFile,
            [Parameter(mandatory)]
                [string]$AdministrativeUnitDefinitionFile,
            [Parameter(mandatory)]
                [string]$AccountsDefinitionFile
         )


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PAG Groups (Role, Tasks, Process, Service, Dept, Resource)
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
        $PAG_Groups_Data  = @()
        $PAG_Groups_Data += Import-csv -Path $DeptGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $RoleGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $TaskGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ProcessGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ServiceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8
        $PAG_Groups_Data += Import-csv -Path $ResourceGroupsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $PAG_Groups_Data = $PAG_Groups_Data | Where ({ $_.GroupName -ne "" })

        # build global array
        $Global:PAG_Groups_Definitions = $PAG_Groups_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Administrative Units
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $AU_Data = Import-csv -Path $AdministrativeUnitDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $AU_Data = $AU_Data | Where { $_.AUDisplayName -ne "" }

        # Build global variable
        $Global:AU_Definitions = $AU_Data

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Admin Accounts
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $AdminAccounts_Data = Import-csv -Path $AccountsDefinitionFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

        # Build global variable
        $Global:Accounts_Definitions = $AdminAccounts_Data
}

Function Build-List-of-Assignments
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitRoleAssignmentsFile,
            [Parameter(mandatory)]
                [string]$GroupRoleAssignmentsFile,
            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile,
            [Parameter(mandatory)]
                [string]$AccountsAssignmentFile
         )


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Administrative Units Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $AdministrativeUnitRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.AdministrativeUnitTag -ne "" })

        # build global array
        $Global:AdministrativeUnitRoleAssignments = $Assignments

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Group Role Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $GroupRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:GroupRoleAssignments = $Assignments

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Group Azure Resources Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:GroupAzResourcesAssignments = $Assignments


    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Admin Accounts Assignments
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        $Assignments  = @()
        $Assignments += Import-csv -Path $AccountsAssignmentFile -Delimiter ";" -Encoding UTF8

        # remove empty lines
        $Assignments = $Assignments | Where ({ $_.GroupTag -ne "" })

        # build global array
        $Global:AccountsAssignment = $Assignments
}


Function CreateUpdate-AdministrativeUnits-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitDefinitionFile
         )

######################################################################################################################
# AU | Administrative Units | Creation
######################################################################################################################

    $AU_Data = Import-csv -Path $AdministrativeUnitDefinitionFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AU_Data = $AU_Data | Where { $_.AUDisplayName -ne "" }

    # Build global variable
    $Global:AU_Definitions = $AU_Data

        ForEach ($Entry in $AU_Data)
            {
                $AUDisplayName         = $Entry.AUDisplayName
                $AUDescription         = $Entry.AUDescription
                $AdministrativeUnitTag = $Entry.AUDescription
                $Visibility            = $Entry.Visibility

                Create-AdministrativeUnit -DisplayName $AUDisplayName `
                                          -Description $AUDescription `
                                          -Visibility $Visibility

               # $AU = Get-MgDirectoryAdministrativeUnit -All:$true
               # $AU = $AU | Where-Object { $_.DisplayName -eq $AdministrativeUnit }
            }
}


Function Assign-Roles-AdministrativeUnits-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AdministrativeUnitRoleAssignmentsFile
         )

######################################################################################################################
# Assignment of Roles to Administrative Units
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to Administrative Unit
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $AdministrativeUnitRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            $GroupTag              = $Entry.GroupTag
            $AdministrativeUnitTag = $Entry.AdministrativeUnitTag
            $RoleDefinitionName    = $Entry.RoleDefinitionName
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            # Get actual group & au, based on tags
            $PAG_Group             = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }
            $AU                    = $Global:AU_Definitions | where-object { $_.AdministrativeUnitTag -eq $AdministrativeUnitTag }
            
            If ($PAG_Group)
                {
                    $PAG_GroupName = $PAG_Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PAG groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            If ($AU)
                {
                    $AUName = $AU.AUDisplayName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any AU with AdministrativeUnitTag $($AdministrativeUnitTag) in the definitions" -ForegroundColor Red
                }

            Write-host "Processing AU Role $($RoleDefinitionName) on AU $($AUName)"

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }


            # Get AU scope Id
                Import-Module Microsoft.Graph.Identity.DirectoryManagement

                $AUs = Get-MgDirectoryAdministrativeUnit

                $AUId = ($AUs | Where-Object { $_.DisplayName -eq $AUName }).id

            # Get Role definition Id
                $roleDefinition = $Global:Role_Group_Definitions_ID | Where-Object { $_.DisplayName -eq $RoleDefinitionName }
                $roleDefinitionId = $roleDefinition.Id

            # Get Group Principal Id
                $Group = Get-MgGroup -Filter "DisplayName eq '$($PAG_Groupname)'"
                $principalId = $Group.Id

            If ( ($AUId) -and ($RoleDefinitionId) -and ($PrincipalId) )
                {
                    Import-Module Microsoft.Graph.Identity.Governance

                    $params = @{
	                    "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
	                    roleDefinitionId = "$($roleDefinitionId)"
	                    principalId = "$($principalId)"
	                    directoryScopeId = "/administrativeUnits/$($AUId)"
                    }

                    New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params
                }
        }
}


Function Assign-Roles-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$GroupRoleAssignmentsFile
         )

######################################################################################################################
# Assignment of PIM for Groups / Privileged Access Group (PAG)
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $GroupRoleAssignmentsFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            $GroupTag            = $Entry.GroupTag
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

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PAG groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            If ($RoleDefinitionName)
                {
                    Create-PIM-Group-Role -GroupName $GroupName `
                                          -RoleDefinitionName $RoleDefinitionName `
                                          -AssignmentType $AssignmentType `
                                          -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                          -Permanent:$Permanent
                }
        }
}


Function Assign-AzResources-Groups-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile
         )

######################################################################################################################
# Assignment of PIM for Azure Resources / Privileged Access Group (PAG)
######################################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # Assignment of PAG to group - used to get eligible/active access to groups after PIM activation of PAG group
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $PAG_Assignments_Data = Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $PAG_Assignments_Data = $PAG_Assignments_Data | Where { $_.GroupTag -ne "" }

    ForEach ($Entry in $PAG_Assignments_Data)
        {
            $GroupTag              = $Entry.GroupTag
            $AzScope               = $Entry.AzScope
            $AzScopePermission     = $Entry.AzScopePermission
            $AssignmentType        = $Entry.AssignmentType
            $NumOfDaysWhenExpire   = $Entry.NumOfDaysWhenExpire
            $Permanent             = $Entry.Permanent

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            # Get actual group, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PAG groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }
            
            Assign-PIM-Group-Resource -GroupName $GroupName `
                                      -AzScope $AzScope `
                                      -AzScopePermission $AzScopePermission `
                                      -AssignmentType $AssignmentType `
                                      -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                      -Permanent:$Permanent `
                                      -ResourceInfoArray $Global:AzureResources_Definitions_ID
        }
}


Function CreateUpdate-Accounts-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AccountsDefinitionFile,
            [Parameter()]
                [string]$DefaultPassword,
            [Parameter()]
                [string]$Path,
            [Parameter()]
                [Object]$Credentials,
            [Parameter()]
                [switch]$OnlyAD = $false,
            [Parameter()]
                [switch]$OnlyID = $false
         )


######################################################################################################################
# Admin Accounts | Create/Update
######################################################################################################################

    $AdminAccounts_Data = Import-csv -Path $AccountsDefinitionFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

    ForEach ($Entry in $AdminAccounts_Data)
        {
            $FirstName              = $Entry.FirstName
            $LastName               = $Entry.LastName
            $Initials               = $Entry.Initials
            $TierLevel              = $Entry.TierLevel
            $TargetUsage            = $Entry.TargetUsage
            $TargetPlatform         = $Entry.TargetPlatform
            $UserType               = $Entry.UserType
            $UserName               = $Entry.UserName
            $UsageLocation          = $Entry.UsageLocation
            $UserPrincipalName      = $Entry.UserPrincipalName
            $DisplayName            = $Entry.DisplayName
            $ForwardMailsToContact  = $Entry.ForwardMailsToContact
            $MailForwardAddress     = $Entry.MailForwardAddress

            If ($ForwardMailsToContact -eq "TRUE")
                {
                    $ForwardMailsToContact = $TRUE
                }
            Else
                {
                    $ForwardMailsToContact = $FALSE
                }

            $PasswordProfile = @{
                                  Password = $DefaultPassword
                                }

            $AD_PasswordProfile = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force 

            $Description = $TargetUsage + ", " + `
                           $TargetPlatform + ", " + `
                           $TierLevel + ", " + `
                           $UserType

            If ( ($TargetPlatform -eq "ID") -and ($OnlyID -eq $true) -and ($OnlyAD -eq $false) )
                {
                    $User = Get-MgUser -Userid $UserPrincipalName -ErrorAction SilentlyContinue
                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $Result = Update-MgUser -UserId $UserPrincipalName `
                                                    -GivenName $FirstName `
                                                    -Surname $LastName `
                                                    -DisplayName $DisplayName `
                                                    -AccountEnabled `
                                                    -MailNickName $UserName `
                                                    -UserPrincipalName $UserPrincipalName `
                                                    -JobTitle $Description `
                                                    -UsageLocation $UsageLocation

                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"
                            $Result = New-MgUser -GivenName $FirstName `
                                                 -Surname $LastName `
                                                 -DisplayName $DisplayName `
                                                 -PasswordProfile $PasswordProfile `
                                                 -AccountEnabled `
                                                 -MailNickName $UserName `
                                                 -UserPrincipalName $UserPrincipalName `
                                                 -JobTitle $Description `
                                                 -UsageLocation $UsageLocation

                        }
                }

            ElseIf ( ($TargetPlatform -eq "AD") -and ($OnlyID -eq $false) -and ($OnlyAD -eq $true) )
                {
                    $User = Get-ADUser -Filter 'UserPrincipalName -eq $UserPrincipalName' `
                                       -Credential $Credentials `
                                       -ErrorAction SilentlyContinue
                    If ($User)
                        {
                            # Update
                            write-host ""
                            Write-host "Updating $($TargetPlatform) user $($DisplayName)"

                            $User | Set-ADUser -GivenName $FirstName `
                                               -Surname $LastName `
                                               -DisplayName $DisplayName `
                                               -Description $Description `
                                               -EmailAddress $UserPrincipalName `
                                               -UserPrincipalName $UserPrincipalName `
                                               -Credential $Credentials

                        }
                    Else
                        {
                            write-host ""
                            Write-host "Creating $($TargetPlatform) account $($DisplayName)"
                            $Result = New-ADUser -Name $UserName `
                                                 -GivenName $FirstName `
                                                 -Surname $LastName `
                                                 -DisplayName $DisplayName `
                                                 -Description $Description `
                                                 -AccountPassword $AD_PasswordProfile `
                                                 -EmailAddress $UserPrincipalName `
                                                 -UserPrincipalName $UserPrincipalName `
                                                 -Path $Path `
                                                 -Enabled:$true `
                                                 -Credential $Credentials
                        }
                }
        }
}


Function Assign-Groups-Accounts-From-file-CSV
{
    [CmdletBinding()]
    param(

            [Parameter(mandatory)]
                [string]$AccountsAssignmentFile
         )

######################################################################################################################
# Admin Accounts | Delegations of PAGs
######################################################################################################################

    $EntraID_Users = $Global:Users_All_ID
    $EntraID_Groups = $Global:Groups_All_ID

    $AdminAccounts_Data = Import-csv -Path $AccountsAssignmentFile -Delimiter ";" -Encoding UTF8

    # remove empty lines
    $AdminAccounts_Data = $AdminAccounts_Data | Where { $_.UserName -ne "" }

    ForEach ($Entry in $AdminAccounts_Data)
        {
            $UserName                  = $Entry.UserName
            $GroupTag                  = $Entry.GroupTag
            $GroupAssignment           = $Entry.GroupAssignment
            $AssignmentType            = $Entry.AssignmentType
            $NumOfDaysWhenExpire       = $Entry.NumOfDaysWhenExpire
            $Permanent                 = $Entry.Permanent

            Write-host ""
            Write-host "Processing account $($UserName)"

            If ($Permanent -eq "TRUE")
                {
                    $Permanent = $TRUE
                }
            Else
                {
                    $Permanent = $FALSE
                }

            $UserInfo = $EntraID_Users | where-object { $_.UserPrincipalName -like "*$($UserName)*" }

            # Get actual group & au, based on tags
            $Group = $Global:PAG_Groups_Definitions | where-object { $_.GroupTag -eq $GroupTag }

            If ($Group)
                {
                    $GroupName = $Group.GroupName
                }
            Else
                {
                    Write-host "ERROR: Could NOT find any PAG groups with GroupTag $($GroupTag) in the definitions" -ForegroundColor Red
                }

            Assign-User-PIM-PAG-Group -UserInfo $UserInfo `
                                      -GroupName $GroupName `
                                      -GroupAllArray $EntraID_Groups `
                                      -AssignmentType $AssignmentType `
                                      -NumOfDaysWhenExpire $NumOfDaysWhenExpire `
                                      -Permanent $Permanent 
        }
}


Function CreateUpdate-Policies-PIM-Roles
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_EndUser_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )


######################################################################################################
# Policies for PIM for Azure AD roles (Microsoft Graph)
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PIM Policies for Roles
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        # List all PIM for Azure AD Roles policies
        Import-Module Microsoft.Graph.Identity.Governance

        $Uri          = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
        $PIM_Policies_Roles = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject

        # counter
        $PIM_Policies_Roles_Counter = ($PIM_Policies_Roles | Measure-Object).count
        $Pos = 0

        # Process policy rules for all PIM policies for roles
        ForEach ($Policy in $PIM_Policies_Roles)
            {
                $Pos = 1 + $Pos
                $PolicyId = $Policy.id 
                write-host ""
                Write-host "[ $($Pos) / $($PIM_Policies_Roles_Counter) ] - Updating rules in PIM for Azure AD Policy [$($PolicyId)]"
                       
                # Create Role Policies
                # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview

                # Expiration
                    <#
                        # Activation maximum duration (hours)
                        Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                 -PolicyId $PolicyId `
                                                 -AssignmentType Assignment `
                                                 -RuleType RoleManagementPolicyExpirationRule `
                                                 -Caller EndUser

                    #>

                        # Allow permanent eligible assignment
                        # Expire eligible assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
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


                        # Allow permanent active assignment
                        # Expire active assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
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

                # Enablement
                        # On activation, require: None, Azure AD Multi-Factor Authentication
                        # Require ticket information on activation
                        # Require justification on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
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


                        # Require Azure Multi-Factor Authentication on active assignment
                        # Require justification on active assignment
                        # Require ticket information on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
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

                    <#
                        # On activation, require: Azure AD Conditional Access authentication context
                            Update-PIM-Policy-Role -RuleId "AuthenticationContext_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyAuthenticationContextRule

                        # Require approval to activate
                            Update-PIM-Policy-Role -RuleId "Approval_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyApprovalRule
                    #>


                # Notification
                        # 	Send notifications when eligible members activate this role: Role activation alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when eligible members activate this role: Notification to activated user (requestor)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when members are assigned as eligible to this role: Role assignment alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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
            }
}


Function CreateUpdate-Policies-PIM-AzResources
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_EndUser_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$GroupAzResourcesAssignmentsFile
         )


######################################################################################################
# Policies for PIM for Azure Resources (Azure Resource Manager)
######################################################################################################

    $Azure_Resources_Data = Import-csv -Path $GroupAzResourcesAssignmentsFile -Delimiter ";" -Encoding UTF8

    $ScopeGrouped = $Azure_Resources_Data | Group-Object -Property AzScope, AzScopePermission

    ForEach ($Group in $ScopeGrouped)
        {
            $Entry = $Group.Group[0]

            $AzScope             = $Entry.AzScope
            $AzDisplayName       = ($Global:AzureResources_Definitions_ID | Where-Object { $_.Id -eq $AzScope }).DisplayName
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


            Write-host ""
            Write-host "Processing Az Resource Scope [ $($AzDisplayName) ]"
            Write-host "$($AzScope) "

            # List all PIM for Azure resources policies
                $Headers = Get-AzAccessTokenManagement

            # Role Policies
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AzResourcesRaw = $Response.Content
                $PIM_Policies_AzResources = $PIM_Policies_AzResourcesRaw | ConvertFrom-Json
                $PIM_Policies_AzResources = $PIM_Policies_AzResources.value

            # Role Assignments
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=2020-10-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_AssignmentRaw = $Response.Content
                $PIM_Policies_Assignments = $PIM_Policies_AssignmentRaw | ConvertFrom-Json
                $PIM_Policies_Assignments = $PIM_Policies_Assignments.value

            # Role Definitions at scope
                $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
                $Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers

                $PIM_Policies_DefinitionsRaw = $Response.Content
                $PIM_Policies_Definitions = $PIM_Policies_DefinitionsRaw | ConvertFrom-Json
                $PIM_Policies_Definitions = $PIM_Policies_Definitions.value

            $DefinitionInScope =  $PIM_Policies_Definitions | Where-Object { $_.properties.rolename -eq $AzScopePermission }
            $PolicyAssignmentInScope = $PIM_Policies_Assignments | Where-Object { $_.properties.roleDefinitionId -eq $DefinitionInScope.id }
            $PolicyInScope = $PolicyAssignmentInScope.properties.policyId.Split("/")[-1]

            # Loop all possible role permissions on Azure resources in PIM - adjust policy settings
            ForEach ($Policy in $PolicyInScope)
                {
                    $Pos = 1 + $Pos

                    # Get all rules for a policy
                    $policyId = $Policy

                    Write-host ""
                    Write-host "Updating policy rules for role $($AzScopePermission) (policy $($PolicyId))"

                    $Headers = Get-AzAccessTokenManagement

                    ############################################################################################
                    # Update policy rule -> Expiration_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_EndUser_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_EndUser_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Assignment_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Assignment_maximumDuration
                                                                                        target = @{
                                                                                                            caller = "Admin"
                                                                                                            operations = @(
			                                                                                                                    "All"
                                                                                                                            )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                    }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Expiration_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Expiration_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyExpirationRule"
                                                                                        isExpirationRequired = $Expiration_Admin_Eligibility_isExpirationRequired
                                                                                        maximumDuration = $Expiration_Admin_Eligibility_maximumDuration
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

            
                    ############################################################################################
                    # Update policy rule -> Enablement_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Enablement_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_Admin_Eligibility_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

 
                    ############################################################################################
                    # Update policy rule -> Enablement_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Enablement_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyEnablementRule"
                                                                                        enabledRules = $Enablement_EndUser_Assignment_enabledRules
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Headers = Get-AzAccessTokenManagement

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson

    
                    ############################################################################################
                    # Update policy rule -> Notification_Admin_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Admin_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Admin_EndUser_recipientType
                                                                                        notificationLevel = $Notification_Admin_EndUser_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_EndUser_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_EndUser_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_EndUser_Assignment
                    ############################################################################################

                        $ruleId = "Notification_Requestor_EndUser_Assignment"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_EndUser_Assignment_notificationType
                                                                                        recipientType = $Notification_Requestor_EndUser_Assignment_recipientType
                                                                                        notificationLevel = $Notification_Requestor_EndUser_Assignment_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_EndUser_Assignment_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Assignment"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Admin_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Admin_Admin_Eligibility"

                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Admin_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Admin_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Admin_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Admin_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled 
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson


                    ############################################################################################
                    # Update policy rule -> Notification_Requestor_Admin_Eligibility
                    ############################################################################################

                        $ruleId = "Notification_Requestor_Admin_Eligibility"
                        $AzRolePolicyBody = [pscustomobject][ordered]@{
                                                    properties = @{
                                                                        rules = @(
                                                                                    @{
                                                                                        id = $ruleId
                                                                                        ruleType = "RoleManagementPolicyNotificationRule"
                                                                                        notificationType = $Notification_Requestor_Admin_Eligibility_notificationType
                                                                                        recipientType = $Notification_Requestor_Admin_Eligibility_recipientType
                                                                                        notificationLevel = $Notification_Requestor_Admin_Eligibility_notificationLevel
                                                                                        notificationRecipients = $Notification_Requestor_Admin_Eligibility_notificationRecipients
                                                                                        isDefaultRecipientsEnabled = $Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
                                                                                        target = @{
                                                                                                    caller = "Admin"
                                                                                                    operations = @(
			                                                                                                        "All"
                                                                                                                    )
                                                                                                    }
                                                                                        level = "Eligibility"
                                                                                        targetObjects = $null
                                                                                        inheritableSettings = $null
                                                                                        enforcedSettings = $null
                                                                                        }
                                                                                    )
                                                                    }
                                                }

                        $Guid = (new-guid).Guid

                        $AzRolePolicyBodyJson = $AzRolePolicyBody | ConvertTo-Json -Depth 20

                        $AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleManagementPolicies/" + $policyId + "?api-version=2020-10-01"
                        $result = invoke-webrequest -UseBasicParsing -Method PATCH -Uri $AzGraphUri -Headers $Headers -Body $AzRolePolicyBodyJson
                }
        }
}


Function CreateUpdate-Policies-PIM-Groups
{

    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [bool]$Expiration_EndUser_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_EndUser_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Assignment_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Assignment_maximumDuration,
            [Parameter(mandatory)]
                [bool]$Expiration_Admin_Eligibility_isExpirationRequired,
            [Parameter(mandatory)]
                [string]$Expiration_Admin_Eligibility_maximumDuration,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Assignment_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_Admin_Eligibility_enabledRules,
            [Parameter(mandatory)]
                [array]$Enablement_EndUser_Assignment_enabledRules,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_EndUser_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_EndUser_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_EndUser_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_EndUser_Assignment_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_EndUser_Assignment_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_EndUser_Assignment_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Admin_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Admin_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Admin_Admin_Eligibility_isDefaultRecipientsEnabled,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_recipientType,
            [Parameter(mandatory)]
                [string]$Notification_Requestor_Admin_Eligibility_notificationLevel,
            [Parameter(mandatory)]
                [array]$Notification_Requestor_Admin_Eligibility_notificationRecipients,
            [Parameter(mandatory)]
                [bool]$Notification_Requestor_Admin_Eligibility_isDefaultRecipientsEnabled
         )

######################################################################################################
# Policies for PIM for Groups (Microsoft Graph)
######################################################################################################

    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------
    # PIM Policies for Groups
    #-------------------------------------------------------------------------------------------------------------------------------------------------------------------

        Write-host "Getting group-info from Entra ID ... Please Wait !"
        $Groups_All = Get-MgGroup -all:$true

        # List all PIM for Groups policies
        $PIM_Policies_Groups = @()

        Write-host "Getting PIM-policies for all groups ... Please Wait !"
        ForEach ($Group in $Groups_All)
            {
                $FilterString = "scopeId eq '$($Group.Id)' and scopeType eq 'Group'"
                $PIM_Policies_Groups += Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '$($Group.Id)' and scopeType eq 'Group'" -ExpandProperty "rules(`$select=id)" -ErrorAction SilentlyContinue
            }

        # counter
        $PIM_Policies_Groups_Counter = ($PIM_Policies_Groups | Measure-Object).count
        $Pos = 0

        # loop through all policies
        ForEach ($Policy in $PIM_Policies_Groups)
            {
                $Pos = 1 + $Pos
                $PolicyId = $Policy.id 
                write-host ""
                Write-host "[ $($Pos) / $($PIM_Policies_Groups_Counter) ] - Updating rules in PIM for Groups Policy [$($PolicyId)]"
                       
                # Create Role Policies
                # https://learn.microsoft.com/en-us/graph/identity-governance-pim-rules-overview

                # Expiration
                    <#
                        # Activation maximum duration (hours)
                        Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                 -PolicyId $PolicyId `
                                                 -AssignmentType Assignment `
                                                 -RuleType RoleManagementPolicyExpirationRule `
                                                 -Caller EndUser

                    #>

                        # Allow permanent eligible assignment
                        # Expire eligible assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
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


                        # Allow permanent active assignment
                        # Expire active assignments after
                            Update-PIM-Policy-Role -RuleId "Expiration_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyExpirationRule `
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

                # Enablement
                        # On activation, require: None, Azure AD Multi-Factor Authentication
                        # Require ticket information on activation
                        # Require justification on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
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


                        # Require Azure Multi-Factor Authentication on active assignment
                        # Require justification on active assignment
                        # Require ticket information on activation
                            Update-PIM-Policy-Role -RuleId "Enablement_Admin_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyEnablementRule `
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

                    <#
                        # On activation, require: Azure AD Conditional Access authentication context
                            Update-PIM-Policy-Role -RuleId "AuthenticationContext_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyAuthenticationContextRule

                        # Require approval to activate
                            Update-PIM-Policy-Role -RuleId "Approval_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyApprovalRule
                    #>


                # Notification
                        # 	Send notifications when eligible members activate this role: Role activation alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when eligible members activate this role: Notification to activated user (requestor)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_EndUser_Assignment" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when members are assigned as eligible to this role: Role assignment alert
                            Update-PIM-Policy-Role -RuleId "Notification_Admin_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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


                        # Send notifications when members are assigned as eligible to this role: Notification to the assigned user (assignee)
                            Update-PIM-Policy-Role -RuleId "Notification_Requestor_Admin_Eligibility" `
                                                     -PolicyId $PolicyId `
                                                     -RuleType PolicyNotificationRule `
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
            }
}


Function CreateUpdate-AD-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [string]$GroupName,
            [Parameter(mandatory)]
                [string]$GroupDescription,
            [Parameter(mandatory)]
                [string]$GroupDisplayName,
            [Parameter(mandatory)]
                [string]$GroupCategory = "Security",
            [Parameter(mandatory)]
                [string]$GroupScope = "Global",
            [Parameter(mandatory)]
                [string]$Path,
            [Parameter(mandatory)]
                [Object]$Credentials
         )

<#
    TROUBLESHOOTING ONLY !!

    $GroupName           = $Role_GroupName
    $GroupDescription    = $Role_GroupDescription
#>

    # Check if group already exist
    Try
        {
            $Group = Get-AdGroup -Identity $GroupName -Credential $Credentials -Properties Description, DisplayName
        }
    Catch
        {
            Write-Host ""
            Write-Host "Creating AD group $($GroupName)"
            $Group = New-ADGroup  -SamAccountName $GroupName `
                                  -Credential $Credentials `
                                  -Description $GroupDescription `
                                  -DisplayName $GroupDisplayName `
                                  -GroupCategory $GroupCategory `
                                  -GroupScope $GroupScope `
                                  -Name $GroupName `
                                  -Path $Path
        }

        If ( ($Group.DisplayName -ne $GroupDisplayName) -or ($Group.Description -ne $GroupDescription ) )
            {
                Write-Host ""
                Write-Host "Updating AD group $($GroupName)"
                $Group | Set-ADGroup -SamAccountName $GroupName `
                                        -Credential $Credentials `
                                        -Description $GroupDescription `
                                        -DisplayName $GroupDisplayName `
                                        -GroupCategory $GroupCategory `
                                        -GroupScope $GroupScope
            }
        Else
            {
                Write-Host ""
                Write-Host "OK - AD group $($GroupName) metadata is updated"
            }
}


Function Sync_Members_PIM-Group-AD-Group
{
    [CmdletBinding()]
    param(
            [Parameter(mandatory)]
                [object]$IDSyncGroupsArray,
            [Parameter(mandatory)]
                [object]$IDUsersArrayAll,
            [Parameter(mandatory)]
                [Object]$IDGroupsArrayAll,
            [Parameter(mandatory)]
                [Object]$Credentials,
            [Parameter()]
                [string]$AccountSearchFor,
            [Parameter()]
                [string]$AccountReplaceWith
         )

<#
    TROUBLESHOOTING ONLY !!

    $IDUsersArrayAll = $EntraID_Users_All

    $IDGroupsArrayAll = $EntraID_Groups_All
    $IDSyncGroupsArray = $AD_Sync_Groups

    $AD_GroupNamePostFix = "_"
    $AD_GroupDisplayNamePostFix = "(synced)"

    $DCServer = "DC1.2linkit.local"

    $Credentials = $AD_Credentials 

#>

    ForEach ($Group in $IDSyncGroupsArray)
        {
            $AD_GroupName = $Group.DisplayName + $AD_GroupNamePostFix
            $ID_GroupName = $Group.DisplayName

            Write-host ""
            Write-host "Validating PIM members for group $($ID_GroupName)"

            # get group members for AD group
            $AD_Group_Members = Get-AdGroupMember -Identity $AD_GroupName -Credential $Credentials
            $AD_Group_Members_TTL = Get-AdGroup $AD_GroupName -Property member –ShowMemberTimeToLive -Credential $Credentials

            import-module Microsoft.Graph.Groups
            $ID_Group = $IDGroupsArrayAll | Where-Object { $_.DisplayName -eq $ID_GroupName }

            Import-Module Microsoft.Graph.Beta.Identity.Governance
            $ID_Group_Members = Get-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleInstance -Filter "groupId eq '$($ID_Group.id)'"

            $ID_Members_Array = @()
            If ($ID_Group_Members)
                {
                    ForEach ($Entry in $ID_Group_Members)
                        {
                            $UserInfo = $IDUsersArrayAll | Where-Object { $_.Id -eq $Entry.PrincipalId }
                            $ID_Members_Array += $UserInfo
                        }
                }

            # Step 1 - Add active PIM members from ID group
                ForEach ($Entry in $ID_Group_Members)
                    {
                        
                        $UserInfo = $IDUsersArrayAll | Where-Object { $_.Id -eq $Entry.PrincipalId }
                        $ID_UserName = $UserInfo.MailNickName
                        $AD_UserName = $ID_UserName.Replace($AccountSearchFor,$AccountReplaceWith)

                        # Calculate PIM session time
                        $PIM_Activation_End   = $Entry.EndDateTime

                        # Workaround if PIM activation happens at the same time as the sync-membership loop checks the PIM schedule
                        # Solution will auto-correct assignment
                        If ([string]::IsNullOrEmpty($PIM_Activation_End))
                            {
                                $PIM_Activation_End = (Get-date)
                                $PIM_Activation_End = $PIM_Activation_End.AddHours(1)
                            }
                        $AD_TimeSpanTotalTTL = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalSeconds
                        $AD_TimeSpanTotalTTL = [Math]::Round($AD_TimeSpanTotalTTL, 0)

                        $AD_TimeSpanTotalMinutes = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalMinutes
                        $AD_TimeSpanTotalMinutes = [Math]::Round($AD_TimeSpanTotalMinutes, 0)
                        $AD_TimeSpanTotalMinutesGroupMemberShip = New-TimeSpan -Minutes $AD_TimeSpanTotalMinutes

                        # Get user Distingushed name to compare TTL in AD with expected TTL from PIM session
                        $User = Get-ADUser $AD_UserName -Credential $Credentials

                        # Get TTL in AD for specific user as member of the group
                        $Actual_User_TTL_info = $AD_Group_Members_TTL.member | Where-Object { $_ -like "*$($User.DistinguishedName)*" }
                        If ($Actual_User_TTL_info)
                            {
                                $PosChar1 = $Actual_User_TTL_info.IndexOf("=")
                                $PosChar2 = $Actual_User_TTL_info.IndexOf(">")
                                $Actual_User_TTL = ($Actual_User_TTL_info.SubString(($PosChar1+1),($PosChar2-1-$PosChar1)))
                                $Actual_User_TTL = [int]$Actual_User_TTL

                                $Compare_Actual_TTL_Expected = $Actual_User_TTL - $AD_TimeSpanTotalTTL
                                Write-host ""
                                Write-host "  Current TTL in AD is $($Actual_User_TTL) for user $($AD_UserName)"
                                Write-host "  Expected TTL from ID PIM-session is $($AD_TimeSpanTotalTTL)"
                                Write-host "  Deviation of seconds is $($Compare_Actual_TTL_Expected)"
                                If ($Compare_Actual_TTL_Expected -in -120..120)
                                    {
                                        Write-host "  Deviation of seconds is acceptable" -ForegroundColor Green
                                        $TTLWindowAccepted = $true
                                    }
                                Else
                                    {
                                        Write-host "  Deviation of seconds is NOT acceptable (+/-2 min)" -ForegroundColor Red
                                        $TTLWindowAccepted = $false
                                    }
                            }
                        Else
                            {
                                    $TTLWindowAccepted = $false
                            }
                            

                        If ( ($AD_UserName -notin $AD_Group_Members.name) -or ($TTLWindowAccepted -eq $false) )
                            {
                                $PIM_Activation_End   = $Entry.EndDateTime
                                $AD_TimeSpanTotalMinutes = ( (Get-date $PIM_Activation_End) - ((Get-Date).ToUniversalTime()) ).TotalMinutes
                                $AD_TimeSpanTotalMinutes = [Math]::Round($AD_TimeSpanTotalMinutes, 0)
                                $AD_TimeSpanTotalMinutesGroupMemberShip = New-TimeSpan -Minutes $AD_TimeSpanTotalMinutes
                       
                                Write-host ""
                                Write-host "  PIM for AD: Adding user $($AD_UserName) with group membership for $($AD_TimeSpanTotalMinutes) min (PIM for AD)" -ForegroundColor Yellow

                                Add-ADGroupMember -Identity $AD_GroupName `
                                                  -Members $AD_UserName `
                                                  -MemberTimeToLive $AD_TimeSpanTotalMinutesGroupMemberShip `
                                                  -Credential $AD_Credentials
                            }
                        Else
                            {
                                Write-host ""
                                Write-host "  PIM for AD: User $($AD_UserName) is already member of $($AD_GroupName)" -ForegroundColor Green
                            }
                    }

            # Step 2 - remove members in AD group, which are not member of Entra ID group
            ForEach ($Entry in $AD_Group_Members)
                {
                        $AD_UserName = $Entry.name
                        $ID_UserName = $AD_UserName.Replace("-AD","-ID")
                        If ($ID_UserName -notin $ID_Members_Array.MailNickName)
                            {
                                Write-host ""
                                Write-host "  PIM for AD: Removing User $($ID_UserName) from group $($AD_GroupName)" -ForegroundColor Yellow
                                Remove-ADGroupMember -Identity $AD_GroupName `
                                                     -Members $AD_UserName `
                                                     -Credential $AD_Credentials `
                                                     -Confirm:$false
                            }
                }
        }
}


<#
Start-ADSyncSyncCycle -PolicyType Delta

Check PAM-support:
Get-ADOptionalFeature -filter "name -eq 'privileged access management feature'"

Enable PAM-support:
Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target 2linkit.local

---------
https://woshub.com/temporary-membership-in-active-directory-groups/
Get-ADOptionalFeature -filter "name -eq 'privileged access management feature'"

Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target 2linkit.local

PS C:\windows\system32> Enable-ADOptionalFeature 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target 2linkit.local
WARNING: Enabling 'Privileged Access Management Feature' on 'CN=Partitions,CN=Configuration,DC=2linkIT,DC=local' is an irreversible action! You will not be able to disable 'Pr
ivileged Access Management Feature' on 'CN=Partitions,CN=Configuration,DC=2linkIT,DC=local' if you proceed.


Windows Server 2016 functional levels
Supported domain controller operating systems:

Windows Server 2022
Windows Server 2019
Windows Server 2016
The minimum requirement to add one a domain controller of one of these versions of Windows Server is a Windows Server 2008 functional level. The domain also has to use DFS-R as the engine to replicate SYSVOL.

Windows Server 2016 forest functional level features
All of the features that are available at the Windows Server 2012 R2 forest functional level, and the following features, are available:
Privileged access management (PAM) using Microsoft Identity Manager (MIM)
#>

