#------------------------------------------------------------------------------------------------
Write-Output "***********************************************************************************************"
Write-Output "PIM Assignment Wizard"
Write-Output ""
Write-Output "Purpose: Create new PIM Assignments using Wizard,based on existing groups, admins, AUs"
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
    $Global:Role_Group_Definitions_ID       = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    Write-host "[ 09 / $($MaxSteps) ] Building list of all Role definitions for Administrative Units in Entra ID ... Please Wait !"
    $Global:Role_AU_Definitions_ID          = $Global:Role_Group_Definitions_ID | `
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
                                                Type = "EntraID_Role_AU"
                                                Description = "Entra ID Role Assignment for Administrative Unit"
                                                },
                                            [PSCustomObject]@{
                                                Type = "Azure_Resource"
                                                Description = "Azure Resource"
                                                },
                                            [PSCustomObject]@{
                                                Type = "PIM_Groups"
                                                Description = "PIM for Groups"
                                                },
                                            [PSCustomObject]@{
                                                Type = "AD_PAG_Resource_Groups"
                                                Description = "Active Directory Resource Group"
                                                },
                                            [PSCustomObject]@{
                                                Type = "AD_PAG_Service_Groups"
                                                Description = "Active Directory Service Group"
                                                }
                                          )

        $Step1_Result  = $Step1_Choices | Select-Object Description, Type | Out-GridView -Title "PIM Assignment Wizard | Step 1/6: Choose TYPE of Assignment" -PassThru


    #-----------------------------------------------------------------------------------------------
    # Step 2 - SCOPE to delegate
    #-----------------------------------------------------------------------------------------------

        If ($Step1_Result.Type -eq "EntraID_Role_Group")
            {
                $Step2_Choices = $Global:Role_Group_Definitions_ID
                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/6: Choose Role to delegate (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "EntraID_Role_AU")
            {
                $Step2_Choices = $Global:Role_AU_Definitions_ID
                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/6: Choose Role to delegate (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "Azure_Resource")
            {
                $Step2_Choices = $Global:AzureResources_Definitions_ID 

                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/6: Choose Azure Resource to delegate (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "PIM_Groups")
            {
                $Step2_Choices = $Global:PAG_Groups_Definitions_ID

                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/6: Choose Entra ID Group to delegate (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "AD_PAG_Resource_Groups")
            {
                $Step2_Choices = $Global:PAG_Groups_Resource_SyncAD_Definitions_ID

                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/7: Choose PAG Resource Group to delegate for PIM for AD (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "AD_PAG_Service_Groups")
            {
                $Step2_Choices = $Global:PAG_Groups_Service_SyncAD_Definitions_ID

                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/7: Choose PAG Service Group to delegate for PIM for AD (SCOPE)" -PassThru
            }


    #-----------------------------------------------------------------------------------------------
    # Step 3 - TYPE of security principal, WHO should be delegated - Admin Account / Group / Administrative Unit
    #-----------------------------------------------------------------------------------------------

        If ($Step1_Result.Type -eq "EntraID_Role_AU")
            {
                $Step3_Result = "Administrative Unit"
            }
        Else
            {
                $Step3_Choices = @("Admin Account","Group")

                $Step3_Result  = $Step3_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 3/6: Choose Type of security principal, WHO should be delegated" -PassThru
            }

    #-----------------------------------------------------------------------------------------------
    # Step 4 - WHO should be delegated
    #-----------------------------------------------------------------------------------------------

        If ($Step3_Result -eq "Admin Account")
            {
                $Step4_Choices = $Global:Accounts_Definitions_ID

                $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Admin Account to delegate (WHO)" -PassThru
            }
        If ($Step3_Result -eq "Group")
            {
                $Step4_Choices = $Global:PAG_Groups_Definitions_ID

                $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Group to delegate (WHO)" -PassThru

            }
        ElseIf ($Step3_Result -eq "Administrative Unit")
            {
                $Step4_Choices = $Global:AU_Definitions_ID

                $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Administrative Unit to delegate (WHERE)" -PassThru
            }

    #-----------------------------------------------------------------------------------------------
    # Step 5 - WHAT level of Permission - only for Azure Resources & Role Assignments for AUs
    # AUs - WHAT level of assignment can be group or admin
    # AzRes - can be any Azure Resource Role
    #-----------------------------------------------------------------------------------------------

        If ($Step1_Result.Type -eq "Azure_Resource")
            {
                $Step5_Choices = $Global:AzureResourcesRole_Definitions_ID
            
                $Step5_Result  = $Step5_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 5/6: Choose Azure Resource Role to assign for the selected Azure scope" -PassThru
            }

        ElseIf ($Step1_Result.Type -eq "EntraID_Role_AU")
            {
                $Step5A_Choices = @("Admin Account","Group")

                $Step5A_Result  = $Step5A_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4A/6: Choose WHO to Assign the selected Role for (WHO)" -PassThru

                Switch ($Step5A_Result)
                    {
                        "Group"         { 
                                            $Step5_Choices = $Global:PAG_Groups_Definitions_ID
                                        }
                        "Admin Account" { 
                                            $Step5_Choices = $Global:Accounts_Definitions_ID
                                        }
                    }

                $Step5_Result  = $Step5_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 5/6: Choose WHO to Assign the selected Role for (WHO)" -PassThru
            }


    #-----------------------------------------------------------------------------------------------
    # Step 6 - Type of Assignment
    #-----------------------------------------------------------------------------------------------

        # AU Role assignments isn't done through PIM. It Assigns a Role to a group or admin on AU
        # Everything else is done through PIM

        If ($Step1_Result.Type -ne "EntraID_Role_AU")
            {

                $Step6_Choices = [PSCustomObject]@(
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Eligible"
                                                        AssignmentLengthDays = 365
                                                        Permanent = $false
                                                        },
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Active"
                                                        AssignmentLengthDays = 365
                                                        Permanent = $false
                                                        }
                                                  )

                $Step6_Result  = $Step6_Choices | Out-GridView -Title "Step 6/6: Choose Type of Assignment (HOW)" -PassThru
            }

    #-----------------------------------------------------------------------------------------------
    # Step 7 - Assignment
    #-----------------------------------------------------------------------------------------------

        If ($Step1_Result.Type -eq "EntraID_Role_Group")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------
                    $RoleSelectedId                 = $Step2_Result.Id
                    $RoleSelectedDisplayName        = $Step2_Result.DisplayName

                    $TypeOfTarget = $Step3_Result
                    $TargetSelectedId               = $Step4_Result.Id
                    $TargetSelectedDisplayName      = $Step4_Result.DisplayName

                    $Assignment_Type                = $Step6_Result.AssignmentType
                    $Assignment_NumOfDaysWhenExpire = $Step6_Result.AssignmentLengthDays
                    $Assignment_Permanent           = $Step6_Result.Permanent

                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    $Justification = "IAC: Assigning role $($RoleSelectedDisplayName) to $($TypeOfTarget) $($TargetSelectedDisplayName)"

                    $params = @{
	                                action = "AdminAssign"
	                                justification = $Justification
	                                directoryScopeId = "/"
                                    roleDefinitionId = $RoleSelectedId
                                    principalId = $TargetSelectedId
                                }

                    If (!($Assignment_Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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


                    ElseIf ($Assignment_Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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
                    
                    If ($Assignment_Type -eq "Eligible")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleSelectedDisplayName) role as Eligible"
                            Write-host "      for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                            New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($Assignment_Type -eq "Active")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleSelectedDisplayName) role as Active"
                            Write-host "      for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                            New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
                        }
            }
        #---------------------------------------------------------------------------------------------------------------------
        ElseIf ($Step1_Result.Type -eq "EntraID_Role_AU")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------

                    $RoleSelectedId            = $Step2_Result.Id
                    $RoleSelectedDisplayName   = $Step2_Result.DisplayName
                    $AUScopeId                 = $Step4_Result.Id
                    $AUScopeDisplayName        = $Step4_Result.DisplayName
                    $TypeOfTarget              = $Step3_Result
                    $TargetSelectedId          = $Step5_Result.Id
                    $TargetSelectedDisplayName = $Step5_Result.DisplayName

                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    $params = @{
	                    "@odata.type" = "#microsoft.graph.unifiedRoleAssignment"
	                    roleDefinitionId = "$($RoleSelectedId)"
	                    principalId = "$($TargetSelectedId)"
	                    directoryScopeId = "/administrativeUnits/$($AUScopeId)"
                    }

                    Write-Host ""
                    Write-Host "PIM - Assigning $($RoleSelectedDisplayName) role"
                    Write-host "      for $($TypeOfTarget) $($TargetSelectedDisplayName)"
                    Write-host "      on Administrative Unit $($AUScopeDisplayName)"

                    New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params
            }
        #---------------------------------------------------------------------------------------------------------------------
        ElseIf ($Step1_Result.Type -eq "Azure_Resource")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------

                    $AzureResourceSelectedId          = $Step2_Result.Id
                    $AzureResourceSelectedDisplayName = $Step2_Result.Name

                    $TypeOfTarget                     = $Step3_Result
                    $TargetSelectedId                 = $Step4_Result.Id
                    $TargetSelectedDisplayName        = $Step4_Result.DisplayName
            
                    $AzRolePermissionId               = $Step5_Result.Id
                    $AzRolePermissionDisplayName      = $Step5_Result.Name

                    $Assignment_Type                  = $Step6_Result.AssignmentType
                    $Assignment_NumOfDaysWhenExpire   = $Step6_Result.AssignmentLengthDays
                    $Assignment_Permanent             = $Step6_Result.Permanent


                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    $roleDefinitionId = $AzureResourceSelectedId + "/providers/Microsoft.Authorization/roleDefinitions/" + $AzRolePermissionId

                    $Justification = "IAC: Assigning role $($AzRolePermissionDisplayName) to $($TypeOfTarget) $($TargetSelectedDisplayName)"

                    If (!($Assignment_Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                            $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                        properties = @{
                                                                            principalId = $TargetSelectedId
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
                    ElseIf ($Assignment_Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ssK")

                            $AzRoleAssignmentBody = [pscustomobject][ordered]@{
                                                        properties = @{
                                                                            principalId = $TargetSelectedId
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

                    Write-Host ""
                    Write-Host "PIM - Assigning $($AzRolePermissionDisplayName) role as $($Assignment_Type)"
                    Write-host "      for $($TypeOfTarget) $($TargetSelectedDisplayName)"
                    Write-Host "      on scope [ $($AzureResourceSelectedDisplayName) ]"
                    Write-host "      $($AzureResourceSelectedId) "

                    If ($AssignmentType -eq "Eligible")
                        {
                            $AzGraphUri = "https://management.azure.com" + $AzureResourceSelectedId + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            $AzGraphUri = "https://management.azure.com" + $AzureResourceSelectedId + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01-preview"
                        }

                    invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson

        <#
                    Try
                        {
                            $Response   = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                        }
                    Catch
                        {
        #>
                }
        #---------------------------------------------------------------------------------------------------------------------
        ElseIf ($Step1_Result.Type -eq "PIM_Groups")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------

                    $PIMGroupSelectedId             = $Step2_Result.Id
                    $PIMGroupSelectedDisplayName    = $Step2_Result.DisplayName

                    $TypeOfTarget                   = $Step3_Result

                    $TargetSelectedId               = $Step4_Result.Id
                    $TargetSelectedDisplayName      = $Step4_Result.DisplayName

                    $Assignment_Type                = $Step6_Result.AssignmentType
                    $Assignment_NumOfDaysWhenExpire = $Step6_Result.AssignmentLengthDays
                    $Assignment_Permanent           = $Step6_Result.Permanent


                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    Import-Module Microsoft.Graph.DeviceManagement.Enrollment

                    $Justification = "IAC: Assigning access to group $($PIMGroupSelectedDisplayName) for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                    $params = @{
	                    accessId = "member"
	                    groupId = $PIMGroupSelectedId
	                    action = "AdminAssign"
	                    justification = $Justification
	                    directoryScopeId = "/"
                        principalId = $TargetSelectedId
                    }

                    If (!($Assignment_Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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
                    ElseIf ($Assignment_Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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

                    Write-Host ""
                    Write-Host "PIM - Assigning $($TypeOfTarget) $($TargetSelectedDisplayName) as $($Assignment_Type)"
                    Write-host "      to group $($PIMGroupSelectedDisplayName)"

                    If ($Assignment_Type -eq "Eligible")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params
                        }
            }
        #---------------------------------------------------------------------------------------------------------------------
        ElseIf ($Step1_Result.Type -eq "AD_PAG_Resource_Groups")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------

                    $PIMGroupSelectedId             = $Step2_Result.Id
                    $PIMGroupSelectedDisplayName    = $Step2_Result.DisplayName

                    $TypeOfTarget                   = $Step3_Result
                    $TargetSelectedId               = $Step4_Result.Id
                    $TargetSelectedDisplayName      = $Step4_Result.DisplayName

                    $Assignment_Type                = $Step6_Result.AssignmentType
                    $Assignment_NumOfDaysWhenExpire = $Step6_Result.AssignmentLengthDays
                    $Assignment_Permanent           = $Step6_Result.Permanent

                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    Import-Module Microsoft.Graph.DeviceManagement.Enrollment

                    $Justification = "IAC: Assigning access to group $($PIMGroupSelectedDisplayName) for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                    $params = @{
	                    accessId = "member"
	                    groupId = $PIMGroupSelectedId
	                    action = "AdminAssign"
	                    justification = $Justification
	                    directoryScopeId = "/"
                        principalId = $TargetSelectedId
                    }

                    If (!($Assignment_Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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
                    ElseIf ($Assignment_Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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

                    Write-Host ""
                    Write-Host "PIM - Assigning $($TypeOfTarget) $($TargetSelectedDisplayName) as $($Assignment_Type)"
                    Write-host "      to group $($PIMGroupSelectedDisplayName)"

                    If ($Assignment_Type -eq "Eligible")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params
                        }
            }
        #---------------------------------------------------------------------------------------------------------------------
        ElseIf ($Step1_Result.Type -eq "AD_PAG_Service_Groups")
            {
                #-----------------------------------------------------------------------
                # Variables
                #-----------------------------------------------------------------------

                    $PIMGroupSelectedId             = $Step2_Result.Id
                    $PIMGroupSelectedDisplayName    = $Step2_Result.DisplayName

                    $TypeOfTarget                   = $Step3_Result
                    $TargetSelectedId               = $Step4_Result.Id
                    $TargetSelectedDisplayName      = $Step4_Result.DisplayName

                    $Assignment_Type                = $Step6_Result.AssignmentType
                    $Assignment_NumOfDaysWhenExpire = $Step6_Result.AssignmentLengthDays
                    $Assignment_Permanent           = $Step6_Result.Permanent

                #-----------------------------------------------------------------------
                # Assignment
                #-----------------------------------------------------------------------

                    Import-Module Microsoft.Graph.DeviceManagement.Enrollment

                    $Justification = "IAC: Assigning access to group $($PIMGroupSelectedDisplayName) for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                    $params = @{
	                    accessId = "member"
	                    groupId = $PIMGroupSelectedId
	                    action = "AdminAssign"
	                    justification = $Justification
	                    directoryScopeId = "/"
                        principalId = $TargetSelectedId
                    }

                    If (!($Assignment_Permanent))
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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
                    ElseIf ($Assignment_Permanent)
                        {
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ssK")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
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

                    Write-Host ""
                    Write-Host "PIM - Assigning $($TypeOfTarget) $($TargetSelectedDisplayName) as $($Assignment_Type)"
                    Write-host "      to group $($PIMGroupSelectedDisplayName)"

                    If ($Assignment_Type -eq "Eligible")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
                        }
                    ElseIf ($AssignmentType -eq "Active")
                        {
                            New-MgBetaIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params
                        }
            }


