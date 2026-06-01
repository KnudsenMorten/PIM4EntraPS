###################################################################################################################
# CSV method
###################################################################################################################

$global:DeptGroupsDefinitionFile                          = "$($global:PathScripts)\DATA\PIM-Definitions-Departments.csv"
$global:DeptGroupsDefinitionFile_LastApplied              = "$($global:PathScripts)\DATA\PIM-Definitions-Departments_LastApplied.csv"
$global:DeptGroupsDefinitionFile_Delta                    = "$($global:PathScripts)\DATA\PIM-Definitions-Departments_Delta.csv"

$global:RoleGroupsDefinitionFile                          = "$($global:PathScripts)\DATA\PIM-Definitions-Roles.csv"
$global:RoleGroupsDefinitionFile_LastApplied              = "$($global:PathScripts)\DATA\PIM-Definitions-Roles_LastApplied.csv"
$global:RoleGroupsDefinitionFile_Delta                    = "$($global:PathScripts)\DATA\PIM-Definitions-Roles_Delta.csv"

$global:TaskGroupsDefinitionFile                          = "$($global:PathScripts)\DATA\PIM-Definitions-Tasks.csv"
$global:TaskGroupsDefinitionFile_LastApplied              = "$($global:PathScripts)\DATA\PIM-Definitions-Tasks_LastApplied.csv"
$global:TaskGroupsDefinitionFile_Delta                    = "$($global:PathScripts)\DATA\PIM-Definitions-Tasks_Delta.csv"

$global:ServiceGroupsDefinitionFile                       = "$($global:PathScripts)\DATA\PIM-Definitions-Services.csv"
$global:ServiceGroupsDefinitionFile_LastApplied           = "$($global:PathScripts)\DATA\PIM-Definitions-Services_LastApplied.csv"
$global:ServiceGroupsDefinitionFile_Delta                 = "$($global:PathScripts)\DATA\PIM-Definitions-Services_Delta.csv"

$global:ProcessGroupsDefinitionFile                       = "$($global:PathScripts)\DATA\PIM-Definitions-Processes.csv"
$global:ProcessGroupsDefinitionFile_LastApplied           = "$($global:PathScripts)\DATA\PIM-Definitions-Processes_LastApplied.csv"
$global:ProcessGroupsDefinitionFile_Delta                 = "$($global:PathScripts)\DATA\PIM-Definitions-Processes_Delta.csv"

$global:ResourceGroupsDefinitionFile                      = "$($global:PathScripts)\DATA\PIM-Definitions-Resources.csv"
$global:ResourceGroupsDefinitionFile_LastApplied          = "$($global:PathScripts)\DATA\PIM-Definitions-Resources_LastApplied.csv"
$global:ResourceGroupsDefinitionFile_Delta                = "$($global:PathScripts)\DATA\PIM-Definitions-Resources_Delta.csv"

$global:AdministrativeUnitDefinitionFile                  = "$($global:PathScripts)\DATA\PIM-Definitions-AU.csv"
$global:AdministrativeUnitDefinitionFile_LastApplied      = "$($global:PathScripts)\DATA\PIM-Definitions-AU_LastApplied.csv"
$global:AdministrativeUnitDefinitionFile_Delta            = "$($global:PathScripts)\DATA\PIM-Definitions-AU_Delta.csv"

$global:AdministrativeUnitRoleAssignmentsFile             = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-AUs.csv"
$global:AdministrativeUnitRoleAssignmentsFile_LastApplied = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-AUs_LastApplied.csv"
$global:AdministrativeUnitRoleAssignmentsFile_Delta       = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-AUs_Delta.csv"

$global:GroupRoleAssignmentsFile                          = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-Groups.csv"
$global:GroupRoleAssignmentsFile_LastApplied              = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-Groups_LastApplied.csv"
$global:GroupRoleAssignmentsFile_Delta                    = "$($global:PathScripts)\DATA\PIM-Assignments-Roles-Groups_Delta.csv"

$global:GroupAzResourcesAssignmentsFile                   = "$($global:PathScripts)\DATA\PIM-Assignments-Azure-Resources.csv"
$global:GroupAzResourcesAssignmentsFile_LastApplied       = "$($global:PathScripts)\DATA\PIM-Assignments-Azure-Resources_LastApplied.csv"
$global:GroupAzResourcesAssignmentsFile_Delta             = "$($global:PathScripts)\DATA\PIM-Assignments-Azure-Resources_Delta.csv"

$global:AccountsAssignmentFile                            = "$($global:PathScripts)\DATA\PIM-Assignments-Admins.csv"
$global:AccountsAssignmentFile_LastApplied                = "$($global:PathScripts)\DATA\PIM-Assignments-Admins_LastApplied.csv"
$global:AccountsAssignmentFile_Delta                      = "$($global:PathScripts)\DATA\PIM-Assignments-Admins_Delta.csv"

$global:PIMForGroupsAssignmentsFile                       = "$($global:PathScripts)\DATA\PIM-Assignments-Groups.csv"
$global:PIMForGroupsAssignmentsFile_LastApplied           = "$($global:PathScripts)\DATA\PIM-Assignments-Groups_LastApplied.csv"
$global:PIMForGroupsAssignmentsFile_Delta                 = "$($global:PathScripts)\DATA\PIM-Assignments-Groups_Delta.csv"

$global:AccountsDefinitionFile                            = "$($global:PathScripts)\DATA\Account-Definitions-Admins.csv"
$global:AccountsDefinitionFile_LastApplied                = "$($global:PathScripts)\DATA\Account-Definitions-Admins_LastApplied.csv"
$global:AccountsDefinitionFile_Delta                      = "$($global:PathScripts)\DATA\Account-Definitions-Admins_Delta.csv"



###################################################################################################################
# SQL CONNECTION
###################################################################################################################
<#

    Import-module sqlserver

    $global:SQLToken = (Get-AzAccessToken -ResourceUrl https://database.windows.net).Token

    Set-AzContext -Subscription "1c197240-8add-4b0b-9997-837227d463d9"


    ## VARIABLES
    $global:CSVDelimiter                           = ";"
    $global:SQLServerName                          = "your-sql.database.windows.net"
    $global:SQLDatabaseName                        = "managedpim"
    $global:SQLTableSchema                         = "dbo"
    $global:SQLTableDefinitionsTasks               = "DefinitionsTasks"
    $global:SQLTableDefinitionsServices            = "DefinitionsServices"
    $global:SQLTableDefinitionsRoles               = "DefinitionsRoles"
    $global:SQLTableDefinitionsDepartments         = "DefinitionsDepartments"
    $global:SQLTableDefinitionsProcesses           = "DefinitionsProcesses"
    $global:SQLTableDefinitionsAU                  = "DefinitionsAU"
    $global:SQLTableDefinitionsResources           = "DefinitionsResources"
    $global:SQLTableDefinitionsAdminAccounts       = "DefinitionsAdminAccounts"
    $global:SQLTableAssignmentsRolesGroups         = "AssignmentsRolesGroups"
    $global:SQLTableAssignmentsRolesAUs            = "AssignmentsRolesAUs"
    $global:SQLTableAssignmentsAzureResources      = "AssignmentsAzureResources"
    $global:SQLTableAssignmentsAdmins              = "AssignmentsAdmins"
#>
