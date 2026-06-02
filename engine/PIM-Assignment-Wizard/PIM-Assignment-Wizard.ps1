<#
.SYNOPSIS
    PIM-Assignment-Wizard - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : PIM-Assignment-Wizard.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
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

    $Context = Get-AzContext

    $MaxSteps = "09"

    Write-host ""
    Write-host "[ 01 / $($MaxSteps) ] Building list of all Users in Entra ID ... Please Wait !"
    $Global:Users_All_ID = Get-MgUser -all:$true

    Write-host "[ 02 / $($MaxSteps) ] Building list of all Groups in Entra ID ... Please Wait !"
    $Global:Groups_All_ID = Get-MgGroup -all:$true

    Write-host "[ 03 / $($MaxSteps) ] Building list of all PIM-Groups in Entra ID ... Please Wait !"
    $Global:PIM_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-*") } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    $Global:Role_Groups_Definitions_ID = $Global:Groups_All_ID | `
                                                Where-Object { ($_.DisplayName -like "PIM-*") -and ($_.IsAssignableToRole -eq $true) } | `
                                                Select-Object DisplayName, Description, Id | Sort-Object -Property DisplayName

    Write-host "[ 04 / $($MaxSteps) ] Building list of all Administrative Units in Entra ID ... Please Wait !"
    $Global:AU_Definitions_ID = Get-MgDirectoryAdministrativeUnit -All:$true | Select-Object DisplayName, Id | Sort-Object -Property DisplayName

    Write-host "[ 05 / $($MaxSteps) ] Building list of all Admin Accounts in Entra ID ... Please Wait !"
    $Global:Accounts_Definitions_ID = $Global:Users_All_ID | `
                                                Where-Object { ( ( ($_.UserPrincipalName -like "Admin-*") -or ($_.UserPrincipalName -like "X-Admin*") ) -and ($_.UserPrincipalName -like "*-ID*") ) } | `
                                                Select-Object DisplayName, GivenName, SurName, Id | Sort-Object -Property DisplayName

    Write-host "[ 06 / $($MaxSteps) ] Building list of all Role definitions for Groups in Entra ID ... Please Wait !"
    $Global:Role_Definitions_ID = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object DisplayName, Id

    Write-host "[ 07 / $($MaxSteps) ] Building list of all Role definitions for Administrative Units in Entra ID ... Please Wait !"
    $Global:Role_AU_Definitions_ID = $Global:Role_Definitions_ID | `
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

    Write-host "[ 08 / $($MaxSteps) ] Building list of all Azure Resources ... Please Wait !"

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

    Write-host "[ 09 / $($MaxSteps) ] Building list of all Azure Resources Roles ... Please Wait !"
    $Global:AzureResourcesRole_Definitions_ID = Get-AzRoleDefinition | `
                                                Select-Object Name, Description, Id | Sort-Object -Property Name



##########################################################################################################################
# Main Program
##########################################################################################################################

$Step1_Result = @{
                    Type = ""
                 }

While ($Step1_Result.Type -ne "Exit")
{
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
                                                Type = "Exit"
                                                Description = "Exit this program"
                                                }
                                          )

        $Step1_Result  = $Step1_Choices | Select-Object Description, Type | Out-GridView -Title "PIM Assignment Wizard | Step 1/6: Choose TYPE of Assignment" -PassThru


    #-----------------------------------------------------------------------------------------------
    # Step 2 - SCOPE to delegate
    #-----------------------------------------------------------------------------------------------

        If ($Step1_Result.Type -eq "EntraID_Role_Group")
            {
                $Step2_Choices = $Global:Role_Definitions_ID | Sort-Object -Property DisplayName
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
                $Step2_Choices = $Global:PIM_Groups_Definitions_ID | Sort-Object -Property DisplayName

                $Step2_Result  = $Step2_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 2/6: Choose Entra ID Group to delegate (SCOPE)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "Exit")
            {
                Break
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

        If ($Step1_Result.Type -eq "EntraID_Role_Group")
            {
                If ($Step3_Result -eq "Admin Account")
                    {
                        $Step4_Choices = $Global:Accounts_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Admin Account to delegate (WHO)" -PassThru
                    }
                ElseIf ($Step3_Result -eq "Group")
                    {
                        $Step4_Choices = $Global:Role_Groups_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Group to delegate (WHO)" -PassThru

                    }
            }
        ElseIf ($Step3_Result -eq "Administrative Unit")
            {
                $Step4_Choices = $Global:AU_Definitions_ID | Sort-Object -Property DisplayName

                $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Administrative Unit to delegate (Target)" -PassThru
            }
        ElseIf ($Step1_Result.Type -eq "PIM_Groups")
            {
                If ($Step3_Result -eq "Admin Account")
                    {
                        $Step4_Choices = $Global:Accounts_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Admin Account to delegate (WHO)" -PassThru
                    }
                ElseIf ($Step3_Result -eq "Group")
                    {
                        $Step4_Choices = $Global:PIM_Groups_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Group to delegate (WHO)" -PassThru
                    }
            }
        ElseIf ($Step1_Result.Type -eq "Azure_Resource")
            {
                If ($Step3_Result -eq "Admin Account")
                    {
                        $Step4_Choices = $Global:Accounts_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Admin Account to delegate (WHO)" -PassThru
                    }
                ElseIf ($Step3_Result -eq "Group")
                    {
                        $Step4_Choices = $Global:PIM_Groups_Definitions_ID | Sort-Object -Property DisplayName

                        $Step4_Result  = $Step4_Choices | Out-GridView -Title "PIM Assignment Wizard | Step 4/6: Choose Group to delegate (WHO)" -PassThru
                    }
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
                                            $Step5_Choices = $Global:Role_Groups_Definitions_ID | Sort-Object -Property DisplayName
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

#        If ($Step1_Result.Type -ne "EntraID_Role_AU")
#            {

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
                                                        },
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Eligible"
                                                        AssignmentLengthDays = 180
                                                        Permanent = $false
                                                        },
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Active"
                                                        AssignmentLengthDays = 180
                                                        Permanent = $false
                                                        },
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Eligible"
                                                        AssignmentLengthDays = 90
                                                        Permanent = $false
                                                        },
                                                    [PSCustomObject]@{
                                                        AssignmentType = "Active"
                                                        AssignmentLengthDays = 90
                                                        Permanent = $false
                                                        }
                                                  )

                $Step6_Result  = $Step6_Choices | Out-GridView -Title "Step 6/6: Choose Type of Assignment (HOW)" -PassThru
 #           }

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

                    $TypeOfTarget                   = $Step3_Result

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

                            $result = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $params
                            $result | fl
                        }
                    ElseIf ($Assignment_Type -eq "Active")
                        {
                            Write-Host ""
                            Write-Host "PIM - Assigning $($RoleSelectedDisplayName) role as Active"
                            Write-host "      for $($TypeOfTarget) $($TargetSelectedDisplayName)"

                            $result = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
                            $result | fl
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

                    $result = New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params
                    $result | fl
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
                            $startDateTime = (Get-date -format "yyyy-MM-ddTHH:mm:ssZ")
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ss.00Z")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ss.00Z")

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
                            $startDateTime = (Get-date ([datetime]::Now.ToUniversalTime()) -format "yyyy-MM-ddTHH:mm:ss.00K")
                            $endDateTime   = (Get-date $StartDateTime).AddDays($Assignment_NumOfDaysWhenExpire)
                            $endDateTime   = (Get-date $endDateTime -format "yyyy-MM-ddTHH:mm:ss.00K")

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

                    If ($Assignment_Type -eq "Eligible")
                        {
                            $AzGraphUri = "https://management.azure.com" + $AzureResourceSelectedId + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01"
                        }
                    ElseIf ($Assignment_Type -eq "Active")
                        {
                            $AzGraphUri = "https://management.azure.com" + $AzureResourceSelectedId + "/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/" + $Guid + "?api-version=2020-10-01"
                        }

                    $result = invoke-webrequest -UseBasicParsing -Method PUT -Uri $AzGraphUri -Headers $Headers -Body $AzRoleAssignmentBodyJson
                    $result | fl
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
                            $result = New-MgIdentityGovernancePrivilegedAccessGroupEligibilityScheduleRequest -BodyParameter $params
                            $result | fl
                        }
                    ElseIf ($Assignment_Type -eq "Active")
                        {
                            $result = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params
                            $result | fl
                        }
            }
        ElseIf ($Step1_Result.Type -eq "Exit")
            {
                Break
            }
}

