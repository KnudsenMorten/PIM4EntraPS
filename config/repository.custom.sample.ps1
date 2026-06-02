###################################################################################################################
# repository.custom.ps1
#
# Customer-owned. Lives only on the customer VM (gitignored).
#
# Wires the $global:*DefinitionFile / *AssignmentsFile path variables that the
# PIM-Baseline-Management-* engines read at runtime.
#
# Layout (v1.0.0+):
#   - Input CSVs   -> SOLUTIONS/PIM4EntraPS/config/<base>.custom.csv (fallback .locked.csv)
#                     Resolved via Get-PimConfigCsv from PIM-Functions.psm1.
#   - State files  -> SOLUTIONS/PIM4EntraPS/output/<base>_LastApplied.csv
#                     SOLUTIONS/PIM4EntraPS/output/<base>_Delta.csv
#                     Resolved via Get-PimOutputPath. Folder is created on demand
#                     and gitignored.
###################################################################################################################

# --- Departments ---
$global:DeptGroupsDefinitionFile                          = Get-PimConfigCsv  -Name 'PIM-Definitions-Departments'
$global:DeptGroupsDefinitionFile_LastApplied              = Get-PimOutputPath -Name 'PIM-Definitions-Departments_LastApplied.csv'
$global:DeptGroupsDefinitionFile_Delta                    = Get-PimOutputPath -Name 'PIM-Definitions-Departments_Delta.csv'

# --- Roles ---
$global:RoleGroupsDefinitionFile                          = Get-PimConfigCsv  -Name 'PIM-Definitions-Roles'
$global:RoleGroupsDefinitionFile_LastApplied              = Get-PimOutputPath -Name 'PIM-Definitions-Roles_LastApplied.csv'
$global:RoleGroupsDefinitionFile_Delta                    = Get-PimOutputPath -Name 'PIM-Definitions-Roles_Delta.csv'

# --- Tasks ---
$global:TaskGroupsDefinitionFile                          = Get-PimConfigCsv  -Name 'PIM-Definitions-Tasks'
$global:TaskGroupsDefinitionFile_LastApplied              = Get-PimOutputPath -Name 'PIM-Definitions-Tasks_LastApplied.csv'
$global:TaskGroupsDefinitionFile_Delta                    = Get-PimOutputPath -Name 'PIM-Definitions-Tasks_Delta.csv'

# --- Services ---
$global:ServiceGroupsDefinitionFile                       = Get-PimConfigCsv  -Name 'PIM-Definitions-Services'
$global:ServiceGroupsDefinitionFile_LastApplied           = Get-PimOutputPath -Name 'PIM-Definitions-Services_LastApplied.csv'
$global:ServiceGroupsDefinitionFile_Delta                 = Get-PimOutputPath -Name 'PIM-Definitions-Services_Delta.csv'

# --- Processes ---
$global:ProcessGroupsDefinitionFile                       = Get-PimConfigCsv  -Name 'PIM-Definitions-Processes'
$global:ProcessGroupsDefinitionFile_LastApplied           = Get-PimOutputPath -Name 'PIM-Definitions-Processes_LastApplied.csv'
$global:ProcessGroupsDefinitionFile_Delta                 = Get-PimOutputPath -Name 'PIM-Definitions-Processes_Delta.csv'

# --- Resources ---
$global:ResourceGroupsDefinitionFile                      = Get-PimConfigCsv  -Name 'PIM-Definitions-Resources'
$global:ResourceGroupsDefinitionFile_LastApplied          = Get-PimOutputPath -Name 'PIM-Definitions-Resources_LastApplied.csv'
$global:ResourceGroupsDefinitionFile_Delta                = Get-PimOutputPath -Name 'PIM-Definitions-Resources_Delta.csv'

# --- Administrative Units ---
$global:AdministrativeUnitDefinitionFile                  = Get-PimConfigCsv  -Name 'PIM-Definitions-AU'
$global:AdministrativeUnitDefinitionFile_LastApplied      = Get-PimOutputPath -Name 'PIM-Definitions-AU_LastApplied.csv'
$global:AdministrativeUnitDefinitionFile_Delta            = Get-PimOutputPath -Name 'PIM-Definitions-AU_Delta.csv'

# --- AU role assignments ---
$global:AdministrativeUnitRoleAssignmentsFile             = Get-PimConfigCsv  -Name 'PIM-Assignments-Roles-AUs'
$global:AdministrativeUnitRoleAssignmentsFile_LastApplied = Get-PimOutputPath -Name 'PIM-Assignments-Roles-AUs_LastApplied.csv'
$global:AdministrativeUnitRoleAssignmentsFile_Delta       = Get-PimOutputPath -Name 'PIM-Assignments-Roles-AUs_Delta.csv'

# --- Group role assignments ---
$global:GroupRoleAssignmentsFile                          = Get-PimConfigCsv  -Name 'PIM-Assignments-Roles-Groups'
$global:GroupRoleAssignmentsFile_LastApplied              = Get-PimOutputPath -Name 'PIM-Assignments-Roles-Groups_LastApplied.csv'
$global:GroupRoleAssignmentsFile_Delta                    = Get-PimOutputPath -Name 'PIM-Assignments-Roles-Groups_Delta.csv'

# --- Azure Resource assignments ---
$global:GroupAzResourcesAssignmentsFile                   = Get-PimConfigCsv  -Name 'PIM-Assignments-Azure-Resources'
$global:GroupAzResourcesAssignmentsFile_LastApplied       = Get-PimOutputPath -Name 'PIM-Assignments-Azure-Resources_LastApplied.csv'
$global:GroupAzResourcesAssignmentsFile_Delta             = Get-PimOutputPath -Name 'PIM-Assignments-Azure-Resources_Delta.csv'

# --- Admin assignments ---
$global:AccountsAssignmentFile                            = Get-PimConfigCsv  -Name 'PIM-Assignments-Admins'
$global:AccountsAssignmentFile_LastApplied                = Get-PimOutputPath -Name 'PIM-Assignments-Admins_LastApplied.csv'
$global:AccountsAssignmentFile_Delta                      = Get-PimOutputPath -Name 'PIM-Assignments-Admins_Delta.csv'

# --- PIM-for-Groups assignments ---
$global:PIMForGroupsAssignmentsFile                       = Get-PimConfigCsv  -Name 'PIM-Assignments-Groups'
$global:PIMForGroupsAssignmentsFile_LastApplied           = Get-PimOutputPath -Name 'PIM-Assignments-Groups_LastApplied.csv'
$global:PIMForGroupsAssignmentsFile_Delta                 = Get-PimOutputPath -Name 'PIM-Assignments-Groups_Delta.csv'

# --- Admin account definitions ---
$global:AccountsDefinitionFile                            = Get-PimConfigCsv  -Name 'Account-Definitions-Admins'
$global:AccountsDefinitionFile_LastApplied                = Get-PimOutputPath -Name 'Account-Definitions-Admins_LastApplied.csv'
$global:AccountsDefinitionFile_Delta                      = Get-PimOutputPath -Name 'Account-Definitions-Admins_Delta.csv'


###################################################################################################################
# SQL CONNECTION (optional; only used by PIM-Baseline-Management-SQL engine)
#
# Uncomment + populate if you sync definitions to Azure SQL instead of CSV files.
###################################################################################################################
<#
    Import-Module sqlserver

    $global:SQLToken = (Get-AzAccessToken -ResourceUrl https://database.windows.net).Token

    Set-AzContext -Subscription "<sql-subscription-id>"

    $global:CSVDelimiter                           = ";"
    $global:SQLServerName                          = "<sqlserver>.database.windows.net"
    $global:SQLDatabaseName                        = "<database>"
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
