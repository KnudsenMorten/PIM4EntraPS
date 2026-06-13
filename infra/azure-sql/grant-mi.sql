-- Grant the Manager/engine Managed Identity a contained DB user in PIM4EntraPS.
-- Run AS the AAD admin (the group/user set in main.bicep), connected to the
-- database over the Private Endpoint (e.g. from a host on the VNet, or via a
-- bastion/jumphost). Replace <MI-DISPLAY-NAME> with the identity's display name
-- (user-assigned MI name, or the App Service / VM / container app name for a
-- system-assigned MI). AAD-only auth -- no SQL login is created.

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'<MI-DISPLAY-NAME>')
    CREATE USER [<MI-DISPLAY-NAME>] FROM EXTERNAL PROVIDER;

-- Least-privilege for the data layer: read + write rows/settings/queue, and
-- create/alter the pim schema objects on first run (Initialize-PimSqlStore).
ALTER ROLE db_datareader ADD MEMBER [<MI-DISPLAY-NAME>];
ALTER ROLE db_datawriter ADD MEMBER [<MI-DISPLAY-NAME>];
ALTER ROLE db_ddladmin   ADD MEMBER [<MI-DISPLAY-NAME>];
GO
