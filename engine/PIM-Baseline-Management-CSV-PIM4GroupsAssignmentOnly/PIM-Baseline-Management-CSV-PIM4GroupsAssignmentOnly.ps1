<#
.SYNOPSIS
    PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly.ps1
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


#####################################################################################################################################
# Step 1/3: Detect delta (changes) between files $PIMForGroupsAssignmentsFile_LastApplied and $PIMForGroupsAssignmentsFile
#####################################################################################################################################

    # Define the paths to the CSV files
    $csv1Path     = $global:PIMForGroupsAssignmentsFile_LastApplied
    $csv2Path     = $global:PIMForGroupsAssignmentsFile
    $deltaCsvPath = $global:PIMForGroupsAssignmentsFile_Delta

    # Read lines from both CSV files
    try {
        $csv1Lines = Get-Content -Path $csv1Path -ErrorAction SilentlyContinue
        $csv2Lines = Get-Content -Path $csv2Path -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Error reading CSV files: $_"
        exit
    }

    # Initialize an array to hold delta lines
    $deltaLines = @()

    # Create hash sets for quick lookups
    $csv1HashSet = [System.Collections.Generic.HashSet[string]]::new()
    If ($csv1Lines) {
        foreach ($line in $csv1Lines[1..$csv1Lines.Count]) {
            $Result = $csv1HashSet.Add($line)
        }
    }

    # Compare each line in csv2 against csv1
    foreach ($line in $csv2Lines[1..$csv2Lines.Count]) {
        if (-not $csv1HashSet.Contains($line)) {
            $deltaLines += $line
        }
    }

    # Add the header to the delta lines if there are differences
    if ($deltaLines.Count -gt 0) {
        $DeltaFound = $true
        $header = $csv2Lines[0]
        $deltaLines = @($header) + $deltaLines

        # Export the delta lines to a new CSV file
        $deltaLines | Out-File -FilePath $deltaCsvPath -Encoding utf8
    } else {
        $DeltaFound = $false
    }


#####################################################################################################################################
# Step 2/3: Process only delta (changes) | Assignment of PIM for Groups / Privileged Access Group (PAG)
#####################################################################################################################################

    If ($DeltaFound) {
        # Set to $null to run all assignments
        $Global:PIM_GroupTag_Scoped_StartsWith = $null     # Use fx. ROLE-MGMT - it uses TargetGroupTag

        Assign-PIMForGroups-From-file-CSV -PIMForGroupsAssignmentsFile $deltaCsvPath
    }

#####################################################################################################################################
# Step 3/3: Update _LastApplied file
#####################################################################################################################################

    If ($DeltaFound) {
        COPY $csv2Path $csv1Path
    }
