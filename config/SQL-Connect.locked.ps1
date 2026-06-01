###################################################################################################################
## INITIAL IMPLEMENTATION (ONE-TIME)
###################################################################################################################

# Enable system managed identity on Automation server

# Query to onboard management/automation server VM using managed identity
<#

CREATE USER MGMT01 FROM EXTERNAL PROVIDER
ALTER ROLE db_owner ADD MEMBER MGMT01

//-----------------------

CREATE USER [name@domain.com] 
FROM EXTERNAL PROVIDER 
WITH DEFAULT_SCHEMA = dbo;  
  
-- add user to role(s) in db 
ALTER ROLE dbmanager ADD MEMBER [name@domain.com]; 
ALTER ROLE loginmanager ADD MEMBER [name@domain.com];

#-------------------

CREATE USER "admin@example.invalid" FROM EXTERNAL PROVIDER WITH DEFAULT_SCHEMA = dbo;  
  
-- add user to role(s) in db 
ALTER ROLE db_owner ADD MEMBER "admin@example.invalid"; 

#>


###################################################################################################################
## CONNECTION
###################################################################################################################

import-module sqlserver
Connect-AzAccount -ManagedService -Subscription "fce4f282-fcc6-43fb-94d8-bf1701b862c3"

$token = (Get-AzAccessToken -ResourceUrl https://database.windows.net).Token

Set-AzContext -Subscription "fce4f282-fcc6-43fb-94d8-bf1701b862c3"


###################################################################################################################
## VARIABLES
###################################################################################################################

$Path           = "C:\SCRIPTS\DATA\"
$csvDelimiter   = ";"
$serverName     = "your-sql.database.windows.net"
$databaseName   = "managedpim"
$tableSchema    = "dbo"


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): PAG-Definitions-*.csv
## TARGET (SQL): Definitions*
###################################################################################################################

$DefinitionArray = @("Tasks","Services","Roles","Departments","Processes","Resources")

ForEach ($DefEntry in $DefinitionArray)
    {
        Write-host ""
        Write-host "Processing $($DefEntry)"
        # Variables
        $csvPath        = $Path + "PAG-Definitions-" + $DefEntry + ".csv"
        $tableName      = "Definitions" + $DefEntry

        ## Import CSV into SQL
        $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

        # NOT WORKING
        # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

        #------------------------
        # Create Table
        #------------------------

        Write-host "Verifying/Creating table name $($tableName)"
        $SQLQuery = @"
        
        USE [$($databaseName)]
        GO

        /* CREATE TABLE WITH SCHEMA */
        IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
            create table [$($tableName)]
		        (GroupName varchar(263),
  	             GroupDescription varchar(263),
			     GroupTag varchar(263), 
			     AdministrativeUnitTag varchar(263), 
			     CPPlatform varchar(263),
			     Plane varchar(263),
			     TierLevel varchar(263),
			     PermissionScope varchar(263),
			     SyncPlatform varchar(263),
			     IsRoleAssignable varchar(263))
        Go
"@

        $SQLQueryString = $SQLQuery | Out-String

        Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


        #------------------------
        # IMPORT DATA INTO TABLE
        #------------------------

        Write-host "Importing/Updating data in table name $($tableName), if not found"

        $SQLQuery = @()
        $SQLQuery += @"
        USE [$($databaseName)]
        GO
"@

        ForEach ($Entry in $Data)
            {

                $SQLQuery += @"
        
                /* INSERT VALUES IN TABLE, IF NOT EXIST */
                BEGIN
                    IF NOT EXISTS (SELECT * FROM $($tableName)
                                   where GroupTag = '$($Entry.GroupTag)')
                        BEGIN
		                    INSERT INTO $($tableName) (GroupName, GroupDescription, GroupTag, AdministrativeUnitTag, CPPlatform, Plane, TierLevel, PermissionScope, SyncPlatform, IsRoleAssignable)
                            VALUES
                               ('$($Entry.GroupName)',
                                '$($Entry.GroupDescription)',
                                '$($Entry.GroupTag)',
                                '$($Entry.AdministrativeUnitTag)',
                                '$($Entry.CPPlatform)',
                                '$($Entry.Plane)',
                                '$($Entry.TierLevel)',
                                '$($Entry.PermissionScope)',
                                '$($Entry.SyncPlatform)',
                                '$($Entry.IsRoleAssignable)')
                        END
                END


                /* UPDATE VALUES IN TABLE */
                UPDATE [dbo].[$($tableName)]
                           Set
                            GroupName = '$($Entry.GroupName)',
                            GroupDescription = '$($Entry.GroupDescription)',
                            AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)',
                            CPPlatform = '$($Entry.CPPlatform)',
                            Plane = '$($Entry.Plane)',
                            TierLevel = '$($Entry.TierLevel)',
                            PermissionScope = '$($Entry.PermissionScope)',
                            SyncPlatform = '$($Entry.SyncPlatform)',
                            IsRoleAssignable = '$($Entry.IsRoleAssignable)'
                           where GroupTag = '$($Entry.GroupTag)'
"@
        }

        $SQLQuery += @"
        GO
"@

        $SQLQueryString = $SQLQuery | Out-String

        $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

        Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString
    }


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): AU-Definitions.csv
## TARGET (SQL): DefinitionsAU
###################################################################################################################
    
    # Variables
    $CSVFile        = "AU-Definitions"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "Definitions" + "AU"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (AUDisplayName varchar(263),
             AUDescription varchar(263),
			 AdministrativeUnitTag varchar(263), 
             Visibility varchar(263),
			 CPPlatform varchar(263),
			 Plane varchar(263),
			 TierLevel varchar(263),
			 PermissionScope varchar(263),
			 SyncPlatform varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)')
                    BEGIN
		                INSERT INTO $($tableName) (AUDisplayName,AUDescription,AdministrativeUnitTag,Visibility,CPPlatform,Plane,TierLevel,PermissionScope,SyncPlatform)
                        VALUES
                           ('$($Entry.AUDisplayName)',
                            '$($Entry.AUDescription)',
                            '$($Entry.AdministrativeUnitTag)',
                            '$($Entry.Visibility)',
                            '$($Entry.CPPlatform)',
                            '$($Entry.Plane)',
                            '$($Entry.TierLevel)',
                            '$($Entry.PermissionScope)',
                            '$($Entry.SyncPlatform)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        AUDisplayName = '$($Entry.AUDisplayName)',
                        AUDescription = '$($Entry.AUDescription)',
                        Visibility = '$($Entry.Visibility)',
                        CPPlatform = '$($Entry.CPPlatform)',
                        Plane = '$($Entry.Plane)',
                        TierLevel = '$($Entry.TierLevel)',
                        PermissionScope = '$($Entry.PermissionScope)',
                        SyncPlatform = '$($Entry.SyncPlatform)'
                       where AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): PAG-Assignments-Roles-Groups
## TARGET (SQL): AssignmentsRolesGroups
###################################################################################################################
    
    # Variables
    $CSVFile        = "PAG-Assignments-Roles-Groups"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "AssignmentsRolesGroups"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (GroupTag varchar(263),
             RoleDefinitionName varchar(263),
             AssignmentType varchar(263),
             NumOfDaysWhenExpire int,
             Permanent varchar(263),
			 CPPlatform varchar(263),
			 Plane varchar(263),
			 TierLevel varchar(263),
			 PermissionScope varchar(263),
			 SyncPlatform varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where GroupTag = '$($Entry.GroupTag)' and RoleDefinitionName = '$($Entry.RoleDefinitionName)' and AssignmentType = '$($Entry.AssignmentType)' and Permanent = '$($Entry.Permanent)')
                    BEGIN
		                INSERT INTO $($tableName) (GroupTag,RoleDefinitionName,AssignmentType,NumOfDaysWhenExpire,Permanent,CPPlatform,Plane,TierLevel,PermissionScope,SyncPlatform)
                        VALUES
                           ('$($Entry.GroupTag)',
                            '$($Entry.RoleDefinitionName)',
                            '$($Entry.AssignmentType)',
                            $($Entry.NumOfDaysWhenExpire),
                            '$($Entry.Permanent)',
                            '$($Entry.CPPlatform)',
                            '$($Entry.Plane)',
                            '$($Entry.TierLevel)',
                            '$($Entry.PermissionScope)',
                            '$($Entry.SyncPlatform)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        GroupTag = '$($Entry.GroupTag)',
                        RoleDefinitionName = '$($Entry.RoleDefinitionName)',
                        AssignmentType = '$($Entry.AssignmentType)',
                        NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire),
                        Permanent = '$($Entry.Permanent)',
                        CPPlatform = '$($Entry.CPPlatform)',
                        Plane = '$($Entry.Plane)',
                        TierLevel = '$($Entry.TierLevel)',
                        PermissionScope = '$($Entry.PermissionScope)',
                        SyncPlatform = '$($Entry.SyncPlatform)'
                       where GroupTag = '$($Entry.GroupTag)' and RoleDefinitionName = '$($Entry.RoleDefinitionName)' and AssignmentType = '$($Entry.AssignmentType)' and Permanent = '$($Entry.Permanent)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): PAG-Assignments-Roles-AUs
## TARGET (SQL): AssignmentsRolesAUs
###################################################################################################################
    
    # Variables
    $CSVFile        = "PAG-Assignments-Roles-AUs"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "AssignmentsRolesAUs"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (GroupTag varchar(263),
             AdministrativeUnitTag varchar(263),
             RoleDefinitionName varchar(263),
             AssignmentType varchar(263),
             NumOfDaysWhenExpire int,
             Permanent varchar(263),
			 CPPlatform varchar(263),
			 Plane varchar(263),
			 TierLevel varchar(263),
			 PermissionScope varchar(263),
			 SyncPlatform varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where GroupTag = '$($Entry.GroupTag)' and AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)' and RoleDefinitionName = '$($Entry.RoleDefinitionName)' and AssignmentType = '$($Entry.AssignmentType)' and Permanent = '$($Entry.Permanent)')
                    BEGIN
		                INSERT INTO $($tableName) (GroupTag,AdministrativeUnitTag, RoleDefinitionName,AssignmentType,NumOfDaysWhenExpire,Permanent,CPPlatform,Plane,TierLevel,PermissionScope,SyncPlatform)
                        VALUES
                           ('$($Entry.GroupTag)',
                            '$($Entry.AdministrativeUnitTag)',
                            '$($Entry.RoleDefinitionName)',
                            '$($Entry.AssignmentType)',
                            $($Entry.NumOfDaysWhenExpire),
                            '$($Entry.Permanent)',
                            '$($Entry.CPPlatform)',
                            '$($Entry.Plane)',
                            '$($Entry.TierLevel)',
                            '$($Entry.PermissionScope)',
                            '$($Entry.SyncPlatform)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        GroupTag = '$($Entry.GroupTag)',
                        AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)',
                        RoleDefinitionName = '$($Entry.RoleDefinitionName)',
                        AssignmentType = '$($Entry.AssignmentType)',
                        NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire),
                        Permanent = '$($Entry.Permanent)',
                        CPPlatform = '$($Entry.CPPlatform)',
                        Plane = '$($Entry.Plane)',
                        TierLevel = '$($Entry.TierLevel)',
                        PermissionScope = '$($Entry.PermissionScope)',
                        SyncPlatform = '$($Entry.SyncPlatform)'
                       where GroupTag = '$($Entry.GroupTag)' and AdministrativeUnitTag = '$($Entry.AdministrativeUnitTag)' and RoleDefinitionName = '$($Entry.RoleDefinitionName)' and AssignmentType = '$($Entry.AssignmentType)' and Permanent = '$($Entry.Permanent)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): Account-Definitions-Admins
## TARGET (SQL): DefinitionsAdminAccounts
###################################################################################################################
    
    # Variables
    $CSVFile        = "Account-Definitions-Admins"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "DefinitionsAdminAccounts"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (FirstName varchar(263),
             LastName varchar(263),
             Initials varchar(263),
             TierLevel varchar(263),
             TargetUsage varchar(263),
             TargetPlatform varchar(263),
			 UserType varchar(263),
			 UserName varchar(263),
			 DisplayName varchar(263),
			 UserPrincipalName varchar(263),
			 UsageLocation varchar(263),
			 ForwardMailsToContact varchar(263),
			 MailForwardAddress varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where UserPrincipalName = '$($Entry.UserPrincipalName)')
                    BEGIN
		                INSERT INTO $($tableName) (FirstName,LastName,Initials,TierLevel,TargetUsage,TargetPlatform,UserType,UserName,DisplayName,UserPrincipalName,UsageLocation,ForwardMailsToContact,MailForwardAddress)
                        VALUES
                           ('$($Entry.FirstName)',
                            '$($Entry.LastName)',
                            '$($Entry.Initials)',
                            '$($Entry.TierLevel)',
                            '$($Entry.TargetUsage)',
                            '$($Entry.TargetPlatform)',
                            '$($Entry.UserType)',
                            '$($Entry.UserName)',
                            '$($Entry.DisplayName)',
                            '$($Entry.UserPrincipalName)',
                            '$($Entry.UsageLocation)',
                            '$($Entry.ForwardMailsToContact)',
                            '$($Entry.MailForwardAddress)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        FirstName = '$($Entry.FirstName)',
                        LastName = '$($Entry.LastName)',
                        Initials = '$($Entry.Initials)',
                        TierLevel = '$($Entry.TierLevel)',
                        TargetUsage = '$($Entry.TargetUsage)',
                        TargetPlatform = '$($Entry.TargetPlatform)',
                        UserType = '$($Entry.UserType)',
                        UserName = '$($Entry.UserName)',
                        DisplayName = '$($Entry.DisplayName)',
                        UsageLocation = '$($Entry.UsageLocation)',
                        ForwardMailsToContact = '$($Entry.ForwardMailsToContact)',
                        MailForwardAddress = '$($Entry.MailForwardAddress)'
                       where UserPrincipalName = '$($Entry.UserPrincipalName)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): PAG-Assignments-Azure-Resources
## TARGET (SQL): AssignmentsAzureResources
###################################################################################################################
    
    # Variables
    $CSVFile        = "PAG-Assignments-Azure-Resources"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "AssignmentsAzureResources"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (GroupTag varchar(263),
             AzScope varchar(1200),
             AzScopePermission varchar(263),
             AssignmentType varchar(263),
             NumOfDaysWhenExpire int,
             Permanent varchar(263),
			 CPPlatform varchar(263),
			 Plane varchar(263),
			 TierLevel varchar(263),
			 PermissionScope varchar(263),
			 SyncPlatform varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where GroupTag = '$($Entry.GroupTag)' and AzScope = '$($Entry.AzScope)' and AzScopePermission = '$($Entry.AzScopePermission)' and AssignmentType = '$($Entry.AssignmentType)' and NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire) and Permanent = '$($Entry.Permanent)')
                    BEGIN
		                INSERT INTO $($tableName) (GroupTag,AzScope, AzScopePermission,AssignmentType,NumOfDaysWhenExpire,Permanent,CPPlatform,Plane,TierLevel,PermissionScope,SyncPlatform)
                        VALUES
                           ('$($Entry.GroupTag)',
                            '$($Entry.AzScope)',
                            '$($Entry.AzScopePermission)',
                            '$($Entry.AssignmentType)',
                            $($Entry.NumOfDaysWhenExpire),
                            '$($Entry.Permanent)',
                            '$($Entry.CPPlatform)',
                            '$($Entry.Plane)',
                            '$($Entry.TierLevel)',
                            '$($Entry.PermissionScope)',
                            '$($Entry.SyncPlatform)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        GroupTag = '$($Entry.GroupTag)',
                        AzScope = '$($Entry.AzScope)',
                        AzScopePermission = '$($Entry.AzScopePermission)',
                        AssignmentType = '$($Entry.AssignmentType)',
                        NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire),
                        Permanent = '$($Entry.Permanent)',
                        CPPlatform = '$($Entry.CPPlatform)',
                        Plane = '$($Entry.Plane)',
                        TierLevel = '$($Entry.TierLevel)',
                        PermissionScope = '$($Entry.PermissionScope)',
                        SyncPlatform = '$($Entry.SyncPlatform)'
                       where GroupTag = '$($Entry.GroupTag)' and AzScope = '$($Entry.AzScope)' and AzScopePermission = '$($Entry.AzScopePermission)' and AssignmentType = '$($Entry.AssignmentType)' and NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire) and Permanent = '$($Entry.Permanent)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


###################################################################################################################
## Initial Import of data from CSV-file to SQL Table in Azure SQL Database
##
## SOURCE (CSV): PAG-Assignments-Admins
## TARGET (SQL): AssignmentsAdmins
###################################################################################################################
    
    # Variables
    $CSVFile        = "PAG-Assignments-Admins"
    $csvPath        = $Path + $CSVFile + ".csv"
    $tableName      = "AssignmentsAdmins"

    Write-host ""
    Write-host "Processing $($CSVFile)"


    ## Import CSV into SQL
    $Data = Import-Csv -Path $csvPath -Delimiter $csvDelimiter

    # NOT WORKING
    # $Data | Write-SqlTableData -ServerInstance $serverName -DatabaseName $databaseName -SchemaName $tableSchema -TableName $tableName -AccessToken $token -Force -Debug

    #------------------------
    # Create Table
    #------------------------

    Write-host "Verifying/Creating table name $($tableName)"
    $SQLQuery = @"
        
    USE [$($databaseName)]
    GO

    /* CREATE TABLE WITH SCHEMA */
    IF OBJECT_ID(N'$($tableName)', N'U') IS NULL
        create table [$($tableName)]
            (Username varchar(263),
             GroupTag varchar(263),
             AssignmentType varchar(263),
             NumOfDaysWhenExpire int,
             Permanent varchar(263),
			 CPPlatform varchar(263),
			 Plane varchar(263),
			 TierLevel varchar(263),
			 PermissionScope varchar(263),
			 SyncPlatform varchar(263))
    Go
"@

    $SQLQueryString = $SQLQuery | Out-String

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString


    #------------------------
    # IMPORT DATA INTO TABLE
    #------------------------

    Write-host "Importing/Updating data in table name $($tableName), if not found"

    $SQLQuery = @()
    $SQLQuery += @"
    USE [$($databaseName)]
    GO
"@

    ForEach ($Entry in $Data)
        {

            $SQLQuery += @"
        
            /* INSERT VALUES IN TABLE, IF NOT EXIST */
            BEGIN
                IF NOT EXISTS (SELECT * FROM $($tableName)
                                where UserName = '$($Entry.UserName)' and GroupTag = '$($Entry.GroupTag)' and AssignmentType = '$($Entry.AssignmentType)' and NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire) and Permanent = '$($Entry.Permanent)')
                    BEGIN
		                INSERT INTO $($tableName) (UserName,GroupTag,AssignmentType,NumOfDaysWhenExpire,Permanent,CPPlatform,Plane,TierLevel,PermissionScope,SyncPlatform)
                        VALUES
                           ('$($Entry.UserName)',
                            '$($Entry.GroupTag)',
                            '$($Entry.AssignmentType)',
                            $($Entry.NumOfDaysWhenExpire),
                            '$($Entry.Permanent)',
                            '$($Entry.CPPlatform)',
                            '$($Entry.Plane)',
                            '$($Entry.TierLevel)',
                            '$($Entry.PermissionScope)',
                            '$($Entry.SyncPlatform)')
                    END
            END


            /* UPDATE VALUES IN TABLE */
            UPDATE [dbo].[$($tableName)]
                       Set
                        UserName = '$($Entry.UserName)',
                        GroupTag = '$($Entry.GroupTag)',
                        AssignmentType = '$($Entry.AssignmentType)',
                        NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire),
                        Permanent = '$($Entry.Permanent)',
                        CPPlatform = '$($Entry.CPPlatform)',
                        Plane = '$($Entry.Plane)',
                        TierLevel = '$($Entry.TierLevel)',
                        PermissionScope = '$($Entry.PermissionScope)',
                        SyncPlatform = '$($Entry.SyncPlatform)'
                       where UserName = '$($Entry.UserName)' and GroupTag = '$($Entry.GroupTag)' and AssignmentType = '$($Entry.AssignmentType)' and NumOfDaysWhenExpire = $($Entry.NumOfDaysWhenExpire) and Permanent = '$($Entry.Permanent)'
"@
    }

    $SQLQuery += @"
    GO
"@

    $SQLQueryString = $SQLQuery | Out-String

    $SQLQueryString | Out-File "C:\SCRIPTS\TEMP\SQLString.txt" -Encoding utf8 -Force

    Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query $SQLQueryString

#-------------------------------

$AssignmentRolesGroups = Invoke-Sqlcmd -ServerInstance $serverName -Database $databaseName  -AccessToken $token -Query "Select * from AssignmentsRolesGroups"
$AssignmentRolesGroups
