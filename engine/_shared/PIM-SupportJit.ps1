# PIM4EntraPS -- just-in-time support access to the PIM database (framework SECAUDIT-1a item 4c, PIM SEC-92 / SEC-92 ALIGN).
#
# THE MODEL (4c, SI's #1021 design -- one text for every product):
#   * CONSENT, write-protected: [pimsupport].[Consent] holds the Support app's id (its SID is derived from it) and the level
#     the customer consented to (none | read | owner). Only an owner-level principal writes it: the schema is dbo's, no
#     product role has DML on it, ALTER on the schema is DENIED to public. Never from the request, never from a table the
#     engine identity can update. The level granted = the LOWER of the requested and the consented level.
#   * MARKERS: [pimsupport].[GrantMarker], ONE row per database per ROLE ADDED, written in the SAME transaction as the role
#     add: role, added, expires (maxUntil, at most 24 h ahead), pre-existing (the role was already held), the grant id.
#     One OPEN marker per user + role (a filtered unique index); a new open moves its end later, never earlier. A table,
#     not an extended property: one row per role, a history that stays after the revoke (RevokedUtc / RevokedBy /
#     LastError / Attempts), and readable by a signed procedure without any right on the user itself.
#   * REVOKE = the markers: ONLY roles whose marker says the grant added them (not pre-existing), THEN the Support app's
#     open sessions in this database are ended. Never a DROP of the user; never the read-only user, the engines' / web /
#     updater users or the admin group.
#   * SIGNED PROCEDURES that take NO principal parameter: usp_SupportGrant (@Level, @Hours, @Reason, @Ticket, @OpenedBy),
#     usp_SupportRevoke (@Mode expired | all, @Source) and usp_SupportState (none). Signed by an in-database certificate
#     whose user is a db_owner member, private key removed after signing, ALTER on the procedures and the schema DENIED to
#     public (altering a signed procedure drops its signature anyway). So the engine and the web app -- never db_owner --
#     can sweep (and the engine can grant, 4b) through EXECUTE alone.
#   * INSTALLING them is ONE support-session step per existing install (Get-PimSupportJitInstallBatches, run by an
#     owner-level sign-in: the one-time job's 'install' mode or a database owner's session). The updater cannot.
#   * THE SWEEP (Invoke-PimSupportJitSweep = usp_SupportRevoke @Mode = expired) runs in every place that runs regularly:
#     every run of the grant job, the heartbeat (uplink) job, the hosted Manager. Idempotent; every revoke audited (-Audit);
#     LOUD (Write-Warning + problems) on any failure; a failed revoke stays open and is retried by every sweeper.
#   * Until the step is run on an install, nothing here exists there: the sweep and the state say 'not installed' and
#     today's standing access stays (SECAUDIT-1a item 4).
#
# Nothing here signs in. Every caller hands in -Sql { param([string]$Query) } -- ONE scalar from the PIM database. The
# procedures answer ONE JSON scalar each. The grant job carries these functions word for word
# (_PimSupportSqlJob.ps1 Get-PimSupportSqlJobFunctionNames), so the job, the heartbeat and the Manager run one implementation.
# PS 5.1 + 7 (no ?. / ??; JSON times are read whether ConvertFrom-Json kept them as text (5.1) or made them [datetime] (7)).
Set-StrictMode -Off

function Get-PimSupportJitSchemaName { <# PURE. The schema of the support-access objects (a literal). #> return 'pimsupport' }
function Get-PimSupportJitVersionMark { <# PURE. The version line every procedure carries (a literal). #> return 'pim-support-jit v1' }
function Get-PimSupportJitSignerPrefix { <# PURE. The name prefix of the signing certificate (a literal). #> return 'pimsupport_signer' }
function Get-PimSupportJitProcedureNames { <# PURE. The three signed procedures (literals). #> return @('usp_SupportGrant', 'usp_SupportRevoke', 'usp_SupportState') }
function Get-PimSupportJitAdminRole { <# PURE. The role an owner-level grant adds (a literal). #> return 'db_owner' }
function Get-PimSupportJitReadOnlyRole { <# PURE. The standing read-only role (a literal). #> return 'db_datareader' }
function Get-PimSupportJitDefaultHours { <# PURE. The default length of a grant (a literal). #> return 8 }
function Get-PimSupportJitMaxHours { <# PURE. The longest a grant may run (a literal). #> return 24 }
function Get-PimSupportJitNotSetUpText { <# PURE. The plain state of an install without the support-session step (a literal). #> return 'time-limited support access is not set up on this install' }
function Get-PimSupportJitLevels { <# PURE. The consent / request levels, lowest first (literals). #> return @('none', 'read', 'owner') }

function Get-PimSupportJitLowerLevel {
    # PURE. The LOWER of two levels (none < read < owner); anything unknown counts as none. The procedure decides the same.
    param([AllowNull()][string]$Requested, [AllowNull()][string]$Consented)
    $lv = @(Get-PimSupportJitLevels)
    $a = [Array]::IndexOf($lv, "$Requested".Trim().ToLowerInvariant()); $b = [Array]::IndexOf($lv, "$Consented".Trim().ToLowerInvariant())
    if ($a -lt 0 -or $b -lt 0) { return 'none' }
    return $lv[[Math]::Min($a, $b)]
}

function Test-PimSupportJitUserName {
    # PURE. A database user name this file puts into a statement (the same rule as _PimSupportSqlAccess.ps1).
    param([AllowNull()][string]$Name)
    return [bool]("$Name" -match '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$')
}

function ConvertTo-PimSupportJitText {
    # PURE. Free text for a marker (reason, ticket, who opened it): safe characters only, at most -Max characters.
    param([AllowNull()][string]$Text, [int]$Max = 120)
    $t = (("$Text" -replace '[^A-Za-z0-9 ._@:#/()+,-]', ' ') -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max).Trim() }
    return $t
}

function Format-PimSupportJitUtc {
    # PURE. A time as the heartbeat and the audit carry it: yyyy-MM-ddTHH:mm:ssZ (UTC, invariant culture).
    param([Parameter(Mandatory)][datetime]$Utc)
    return $Utc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-PimSupportJitUtc {
    # PURE. A time from a procedure's answer -> a UTC [datetime], or $null. Text yyyy-MM-ddTHH:mm:ss[.fff]Z (5.1 keeps the
    # text) or a [datetime] (7's ConvertFrom-Json makes one). Never the local culture, never a guess.
    param([AllowNull()]$Value)
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $fmts = [string[]]@('yyyy-MM-ddTHH:mm:ssZ', 'yyyy-MM-ddTHH:mm:ss.fffZ', 'yyyy-MM-ddTHH:mm:ss.fffffffZ')
    if ([datetime]::TryParseExact("$Value".Trim(), $fmts, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function ConvertTo-PimSupportJitSqlText {
    # PURE. A value as an N'...' literal (quotes doubled), or NULL.
    param([AllowNull()][string]$Text)
    if ($null -eq $Text -or "$Text" -eq '') { return 'NULL' }
    return "N'" + "$Text".Replace("'", "''") + "'"
}

# ======================================================================================================== the SQL objects
function Get-PimSupportJitTableSql {
    # PURE. The consent table (one row) and the marker table (one row per role added), dbo's schema. Idempotent.
    $s = Get-PimSupportJitSchemaName
    return @"
IF SCHEMA_ID(N'$s') IS NULL EXEC(N'CREATE SCHEMA [$s] AUTHORIZATION [dbo];');
IF OBJECT_ID(N'[$s].[Consent]') IS NULL
    CREATE TABLE [$s].[Consent] (
        Id           TINYINT          NOT NULL CONSTRAINT PK_PimSupportConsent PRIMARY KEY CONSTRAINT CK_PimSupportConsent_One CHECK (Id = 1),
        SupportAppId UNIQUEIDENTIFIER NOT NULL,
        UserName     SYSNAME          NOT NULL,
        ConsentLevel NVARCHAR(10)     NOT NULL CONSTRAINT CK_PimSupportConsent_Level CHECK (ConsentLevel IN (N'none', N'read', N'owner')),
        SetUtc       DATETIME2(0)     NOT NULL,
        SetBy        NVARCHAR(120)    NOT NULL);
IF OBJECT_ID(N'[$s].[GrantMarker]') IS NULL
BEGIN
    CREATE TABLE [$s].[GrantMarker] (
        MarkerId    INT IDENTITY(1, 1) NOT NULL CONSTRAINT PK_PimSupportGrantMarker PRIMARY KEY,
        GrantId     UNIQUEIDENTIFIER   NOT NULL,
        UserSid     VARBINARY(85)      NOT NULL,
        RoleName    SYSNAME            NOT NULL,
        AddedUtc    DATETIME2(0)       NOT NULL,
        ExpiresUtc  DATETIME2(0)       NOT NULL,
        PreExisting BIT                NOT NULL,
        Reason      NVARCHAR(120)      NULL,
        Ticket      NVARCHAR(40)       NULL,
        OpenedBy    NVARCHAR(120)      NULL,
        RevokedUtc  DATETIME2(0)       NULL,
        RevokedBy   NVARCHAR(20)       NULL,
        Attempts    INT                NOT NULL CONSTRAINT DF_PimSupportGrantMarker_Attempts DEFAULT (0),
        LastError   NVARCHAR(400)      NULL);
    CREATE UNIQUE INDEX UX_PimSupportGrantMarker_Open ON [$s].[GrantMarker] (UserSid, RoleName) WHERE RevokedUtc IS NULL;
END
"@
}

function Get-PimSupportJitProcedureText {
    <#
      PURE. The three procedures. NO principal parameter: the Support app comes from [Consent]. Every rule is checked INSIDE
      (a signed module never trusts its caller); names are QUOTENAME'd; each answers ONE JSON scalar.
    #>
    param([Parameter(Mandatory)][ValidateSet('usp_SupportGrant', 'usp_SupportRevoke', 'usp_SupportState')][string]$Name)
    $s = Get-PimSupportJitSchemaName; $m = Get-PimSupportJitVersionMark
    $t = @{}
    $t['usp_SupportGrant'] = @"
CREATE OR ALTER PROCEDURE [$s].[usp_SupportGrant]
    @Level    NVARCHAR(10),
    @Hours    INT,
    @Reason   NVARCHAR(120) = NULL,
    @Ticket   NVARCHAR(40)  = NULL,
    @OpenedBy NVARCHAR(120) = NULL
AS
BEGIN
    -- $m -- framework SECAUDIT-1a 4c. NO principal parameter: the Support app and its consented level come from [$s].[Consent].
    SET NOCOUNT ON; SET XACT_ABORT ON;
    DECLARE @app UNIQUEIDENTIFIER, @user SYSNAME, @consent NVARCHAR(10), @sid VARBINARY(16), @granted NVARCHAR(10),
            @now DATETIME2(0) = SYSUTCDATETIME(), @until DATETIME2(0), @grant UNIQUEIDENTIFIER = NEWID(), @s NVARCHAR(400),
            @pre BIT, @added INT = 0, @extended INT = 0;
    SELECT @app = SupportAppId, @user = UserName, @consent = ConsentLevel FROM [$s].[Consent] WHERE Id = 1;
    IF @app IS NULL OR @consent IS NULL OR @consent = N'none'
        THROW 51101, N'usp_SupportGrant: no consent to support access is recorded in this database.', 1;
    IF @Level IS NULL OR @Level NOT IN (N'read', N'owner') THROW 51102, N'usp_SupportGrant: the level must be read or owner.', 1;
    IF @Hours IS NULL OR @Hours < 1 OR @Hours > 24 THROW 51103, N'usp_SupportGrant: the hours must be 1 to 24.', 1;
    -- the LOWER of the requested and the consented level
    SET @granted = CASE WHEN @Level = N'owner' AND @consent = N'owner' THEN N'owner' ELSE N'read' END;
    SET @until = DATEADD(HOUR, @Hours, @now);
    SET @sid = CAST(@app AS VARBINARY(16));
    -- the STANDING read-only user first (4a: it exists before any admin right is given)
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE sid = @sid)
    BEGIN
        IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @user)
            THROW 51104, N'usp_SupportGrant: another principal already has the Support user''s name -- an owner must resolve it.', 1;
        SET @s = N'CREATE USER ' + QUOTENAME(@user) + N' WITH SID = ' + CONVERT(NVARCHAR(40), @sid, 1) + N', TYPE = E;';
        EXEC sys.sp_executesql @s;
    END
    SELECT @user = name FROM sys.database_principals WHERE sid = @sid;
    IF IS_ROLEMEMBER(N'db_datareader', @user) = 0
    BEGIN SET @s = N'ALTER ROLE [db_datareader] ADD MEMBER ' + QUOTENAME(@user) + N';'; EXEC sys.sp_executesql @s; END
    IF @granted = N'owner'
    BEGIN
        -- ONE marker per role added, in the SAME transaction as the role add; a new open extends the open marker
        BEGIN TRANSACTION;
        IF EXISTS (SELECT 1 FROM [$s].[GrantMarker] WITH (UPDLOCK, HOLDLOCK) WHERE UserSid = @sid AND RoleName = N'db_owner' AND RevokedUtc IS NULL)
        BEGIN
            SELECT @grant = GrantId, @pre = PreExisting FROM [$s].[GrantMarker] WHERE UserSid = @sid AND RoleName = N'db_owner' AND RevokedUtc IS NULL;
            UPDATE [$s].[GrantMarker] SET ExpiresUtc = CASE WHEN ExpiresUtc > @until THEN ExpiresUtc ELSE @until END
             WHERE UserSid = @sid AND RoleName = N'db_owner' AND RevokedUtc IS NULL;
            IF @pre = 0 AND IS_ROLEMEMBER(N'db_owner', @user) = 0
            BEGIN SET @s = N'ALTER ROLE [db_owner] ADD MEMBER ' + QUOTENAME(@user) + N';'; EXEC sys.sp_executesql @s; SET @added = 1; END
            SET @extended = 1;
        END
        ELSE
        BEGIN
            SET @pre = CASE WHEN IS_ROLEMEMBER(N'db_owner', @user) = 1 THEN 1 ELSE 0 END;
            INSERT INTO [$s].[GrantMarker] (GrantId, UserSid, RoleName, AddedUtc, ExpiresUtc, PreExisting, Reason, Ticket, OpenedBy)
                VALUES (@grant, @sid, N'db_owner', @now, @until, @pre, LEFT(@Reason, 120), LEFT(@Ticket, 40), LEFT(@OpenedBy, 120));
            IF @pre = 0
            BEGIN SET @s = N'ALTER ROLE [db_owner] ADD MEMBER ' + QUOTENAME(@user) + N';'; EXEC sys.sp_executesql @s; SET @added = 1; END
        END
        COMMIT TRANSACTION;
    END
    SELECT (SELECT CASE WHEN @granted = N'owner' THEN @grant END AS grantId, @granted AS level, @Level AS requested, @consent AS consented,
                   @user AS userName, @added AS rolesAdded, @extended AS extended, ISNULL(@pre, 0) AS preExisting,
                   CONVERT(NVARCHAR(20), (SELECT MAX(ExpiresUtc) FROM [$s].[GrantMarker] WHERE UserSid = @sid AND RevokedUtc IS NULL), 126) + N'Z' AS untilUtc,
                   CASE WHEN IS_ROLEMEMBER(N'db_datareader', @user) = 1 THEN 1 ELSE 0 END AS readOnly,
                   CASE WHEN IS_ROLEMEMBER(N'db_owner', @user) = 1 THEN 1 ELSE 0 END AS inOwner
            FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS result;
END
"@
    $t['usp_SupportRevoke'] = @"
CREATE OR ALTER PROCEDURE [$s].[usp_SupportRevoke]
    @Mode   NVARCHAR(10),
    @Source NVARCHAR(20) = NULL
AS
BEGIN
    -- $m -- framework SECAUDIT-1a 4c. NO principal parameter: only the users the open markers name are touched.
    SET NOCOUNT ON;
    IF @Mode IS NULL OR @Mode NOT IN (N'expired', N'all') THROW 51111, N'usp_SupportRevoke: the mode must be expired or all.', 1;
    DECLARE @now DATETIME2(0) = SYSUTCDATETIME(), @id INT, @sid VARBINARY(85), @role SYSNAME, @pre BIT, @user SYSNAME,
            @s NVARCHAR(400), @err NVARCHAR(400), @spid INT, @ended INT = 0;
    DECLARE @done TABLE (MarkerId INT, GrantId UNIQUEIDENTIFIER, RoleName SYSNAME, UserName SYSNAME NULL, ExpiresUtc DATETIME2(0),
                         PreExisting BIT, Removed BIT, Error NVARCHAR(400) NULL);
    DECLARE @sids TABLE (UserSid VARBINARY(85) PRIMARY KEY);
    DECLARE m CURSOR LOCAL FAST_FORWARD FOR
        SELECT MarkerId, UserSid, RoleName, PreExisting FROM [$s].[GrantMarker]
         WHERE RevokedUtc IS NULL AND (@Mode = N'all' OR ExpiresUtc <= @now);
    OPEN m; FETCH NEXT FROM m INTO @id, @sid, @role, @pre;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @user = (SELECT name FROM sys.database_principals WHERE sid = @sid); SET @err = NULL;
        BEGIN TRY
            BEGIN TRANSACTION;
            -- ONLY a role the grant ADDED (not pre-existing), and only the role the marker names
            IF @pre = 0 AND @user IS NOT NULL AND @role = N'db_owner' AND IS_ROLEMEMBER(@role, @user) = 1
            BEGIN SET @s = N'ALTER ROLE ' + QUOTENAME(@role) + N' DROP MEMBER ' + QUOTENAME(@user) + N';'; EXEC sys.sp_executesql @s; END
            UPDATE [$s].[GrantMarker] SET RevokedUtc = @now, RevokedBy = LEFT(ISNULL(@Source, N'unknown'), 20), Attempts = Attempts + 1, LastError = NULL
             WHERE MarkerId = @id;
            COMMIT TRANSACTION;
            IF NOT EXISTS (SELECT 1 FROM @sids WHERE UserSid = @sid) INSERT INTO @sids (UserSid) VALUES (@sid);
        END TRY
        BEGIN CATCH
            IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
            SET @err = LEFT(ERROR_MESSAGE(), 400);
            UPDATE [$s].[GrantMarker] SET Attempts = Attempts + 1, LastError = @err WHERE MarkerId = @id;
        END CATCH
        INSERT INTO @done (MarkerId, GrantId, RoleName, UserName, ExpiresUtc, PreExisting, Removed, Error)
            SELECT MarkerId, GrantId, RoleName, @user, ExpiresUtc, PreExisting, CASE WHEN @err IS NULL AND @pre = 0 THEN 1 ELSE 0 END, @err
              FROM [$s].[GrantMarker] WHERE MarkerId = @id;
        FETCH NEXT FROM m INTO @id, @sid, @role, @pre;
    END
    CLOSE m; DEALLOCATE m;
    -- THEN end the Support app's open sessions in this database: a session opened before the end never keeps the right.
    -- Whether this signature may SEE other sessions is said, not assumed: Azure SQL Database shows the database's sessions
    -- with VIEW DATABASE STATE (db_owner has it); a SQL Server instance only with VIEW SERVER STATE (a server right). A
    -- session that could not be ended, or sessions that could not be seen, are reported -- never silently "0 ended".
    DECLARE @canSee BIT = CASE WHEN EXISTS (SELECT 1 FROM fn_my_permissions(NULL, N'SERVER') WHERE permission_name = N'VIEW SERVER STATE')
                                 OR (CONVERT(INT, SERVERPROPERTY('EngineEdition')) IN (5, 8) AND EXISTS (SELECT 1 FROM fn_my_permissions(NULL, N'DATABASE') WHERE permission_name = N'VIEW DATABASE STATE'))
                               THEN 1 ELSE 0 END;
    DECLARE @notEnded INT = 0, @killErr NVARCHAR(400) = NULL, @lg NVARCHAR(256), @olg NVARCHAR(256);
    DECLARE @killed TABLE (SessionId INT, LoginName NVARCHAR(256), OriginalLogin NVARCHAR(256));
    DECLARE k CURSOR LOCAL FAST_FORWARD FOR
        SELECT es.session_id, es.login_name, es.original_login_name FROM sys.dm_exec_sessions es
         WHERE es.session_id <> @@SPID AND es.is_user_process = 1
           AND EXISTS (SELECT 1 FROM @sids x WHERE x.UserSid = es.original_security_id OR x.UserSid = es.security_id);
    OPEN k; FETCH NEXT FROM k INTO @spid, @lg, @olg;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY SET @s = N'KILL ' + CAST(@spid AS NVARCHAR(10)) + N';'; EXEC (@s); SET @ended = @ended + 1; INSERT INTO @killed VALUES (@spid, @lg, @olg); END TRY
        BEGIN CATCH SET @notEnded = @notEnded + 1; SET @killErr = LEFT(ERROR_MESSAGE(), 400); END CATCH
        FETCH NEXT FROM k INTO @spid, @lg, @olg;
    END
    CLOSE k; DEALLOCATE k;
    SELECT (SELECT @Mode AS mode, (SELECT COUNT(*) FROM @done) AS found, @ended AS sessionsEnded, @notEnded AS sessionsNotEnded,
                   @canSee AS sessionsChecked, @killErr AS sessionError,
                   (SELECT SessionId AS id, LoginName AS login, OriginalLogin AS originalLogin FROM @killed FOR JSON PATH) AS endedSessions,
                   (SELECT GrantId AS grantId, RoleName AS role, UserName AS userName, CONVERT(NVARCHAR(20), ExpiresUtc, 126) + N'Z' AS expiresUtc,
                           PreExisting AS preExisting, Removed AS removed FROM @done WHERE Error IS NULL FOR JSON PATH) AS revoked,
                   (SELECT GrantId AS grantId, RoleName AS role, UserName AS userName, CONVERT(NVARCHAR(20), ExpiresUtc, 126) + N'Z' AS expiresUtc,
                           Error AS error FROM @done WHERE Error IS NOT NULL FOR JSON PATH) AS failed,
                   (SELECT RoleName AS role, CONVERT(NVARCHAR(20), ExpiresUtc, 126) + N'Z' AS expiresUtc FROM [$s].[GrantMarker]
                     WHERE RevokedUtc IS NULL FOR JSON PATH) AS [open]
            FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS result;
END
"@
    $t['usp_SupportState'] = @"
CREATE OR ALTER PROCEDURE [$s].[usp_SupportState]
AS
BEGIN
    -- $m -- framework SECAUDIT-1a 4c. Read-only. NO parameter at all.
    SET NOCOUNT ON;
    DECLARE @app UNIQUEIDENTIFIER, @consent NVARCHAR(10), @sid VARBINARY(16), @user SYSNAME;
    SELECT @app = SupportAppId, @consent = ConsentLevel FROM [$s].[Consent] WHERE Id = 1;
    IF @app IS NOT NULL BEGIN SET @sid = CAST(@app AS VARBINARY(16)); SELECT @user = name FROM sys.database_principals WHERE sid = @sid; END
    SELECT (SELECT ISNULL(@consent, N'none') AS consented,
                   CASE WHEN @user IS NOT NULL AND IS_ROLEMEMBER(N'db_datareader', @user) = 1 THEN 1 ELSE 0 END AS readOnly,
                   CASE WHEN @user IS NOT NULL AND IS_ROLEMEMBER(N'db_owner', @user) = 1 THEN 1 ELSE 0 END AS inOwner,
                   (SELECT COUNT(*) FROM [$s].[GrantMarker] WHERE RevokedUtc IS NULL) AS openMarkers,
                   (SELECT COUNT(*) FROM [$s].[GrantMarker] WHERE RevokedUtc IS NULL AND ExpiresUtc <= SYSUTCDATETIME()) AS expiredOpen,
                   (SELECT COUNT(*) FROM [$s].[GrantMarker] mk WHERE mk.RevokedUtc IS NULL AND mk.PreExisting = 0
                       AND NOT EXISTS (SELECT 1 FROM sys.database_role_members rm JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
                                       JOIN sys.database_principals p ON p.principal_id = rm.member_principal_id WHERE r.name = mk.RoleName AND p.sid = mk.UserSid)) AS halfDone,
                   CONVERT(NVARCHAR(20), (SELECT MAX(ExpiresUtc) FROM [$s].[GrantMarker] WHERE RevokedUtc IS NULL), 126) + N'Z' AS jitUntil,
                   (SELECT COUNT(*) FROM [$s].[GrantMarker] WHERE AddedUtc >= DATEADD(HOUR, -24, SYSUTCDATETIME())) AS opened24h,
                   (SELECT COUNT(*) FROM [$s].[GrantMarker] WHERE RevokedUtc >= DATEADD(HOUR, -24, SYSUTCDATETIME())) AS closed24h,
                   -- real SQL (test VM 2026-11-02): the schema deny does not stop a DDL-admin member from making a NEW object in this
                   -- schema. Such an object is never signed and nobody may run it -- but it is REPORTED, never left unseen.
                   (SELECT COUNT(*) FROM sys.objects o WHERE o.schema_id = SCHEMA_ID(N'$s') AND o.type IN ('U', 'V', 'P', 'PC', 'FN', 'IF', 'TF', 'TR', 'SN')
                       AND o.name NOT IN (N'Consent', N'GrantMarker', N'usp_SupportGrant', N'usp_SupportRevoke', N'usp_SupportState')) AS foreignObjects
            FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS result;
END
"@
    return $t[$Name]
}

function Get-PimSupportJitInstallBatches {
    <#
      PURE. THE SUPPORT-SESSION STEP (4c: one per existing install; the updater cannot), run by an OWNER-LEVEL sign-in.
      Idempotent. Batches, in order:
        1 the schema + the two tables
        2 the consent (the customer's level for this Support app), written here and nowhere else
        3 the STANDING read-only user of the Support app (4a: before any admin right is made just-in-time)
        4 the three procedures (only when missing or another version -- re-creating one drops its signature)
        5 SIGN when any is unsigned: earlier signers out, a NEW certificate (random password made inside SQL, never
          returned), its user a db_owner member, ADD SIGNATURE to all three, the private key REMOVED
        6 ALTER on the procedures and on the schema DENIED to public; EXECUTE for the engine role (grant, revoke, state:
          4b's grant job runs as the engine) and the web role (revoke, state: the Manager sweeps)
    #>
    param([Parameter(Mandatory)][string]$SupportAppId, [Parameter(Mandatory)][ValidateSet('none', 'read', 'owner')][string]$ConsentLevel,
          [string]$UserName = 'invardia-support', [string]$SetBy = '')
    $g = [guid]::Empty
    if (-not [guid]::TryParse("$SupportAppId".Trim(), [ref]$g) -or $g -eq [guid]::Empty) { throw "Get-PimSupportJitInstallBatches: '$SupportAppId' is not an application (client) id." }
    if (-not (Test-PimSupportJitUserName -Name $UserName)) { throw "Get-PimSupportJitInstallBatches: '$UserName' is not a safe database user name." }
    $s = Get-PimSupportJitSchemaName; $m = Get-PimSupportJitVersionMark; $pfx = Get-PimSupportJitSignerPrefix
    $procs = @(Get-PimSupportJitProcedureNames)
    $b = New-Object System.Collections.Generic.List[string]
    [void]$b.Add((Get-PimSupportJitTableSql))
    $by = ConvertTo-PimSupportJitSqlText -Text (ConvertTo-PimSupportJitText -Text $SetBy -Max 120)
    if ($by -eq 'NULL') { $by = "N'support-session step'" }
    [void]$b.Add(@"
MERGE [$s].[Consent] AS t
USING (SELECT CAST(1 AS TINYINT) AS Id, CAST('$g' AS UNIQUEIDENTIFIER) AS SupportAppId, $(ConvertTo-PimSupportJitSqlText -Text $UserName) AS UserName, N'$ConsentLevel' AS ConsentLevel) AS v ON t.Id = v.Id
WHEN MATCHED THEN UPDATE SET SupportAppId = v.SupportAppId, UserName = v.UserName, ConsentLevel = v.ConsentLevel, SetUtc = SYSUTCDATETIME(), SetBy = $by
WHEN NOT MATCHED THEN INSERT (Id, SupportAppId, UserName, ConsentLevel, SetUtc, SetBy) VALUES (v.Id, v.SupportAppId, v.UserName, v.ConsentLevel, SYSUTCDATETIME(), $by);
"@)
    if ($ConsentLevel -ne 'none') {
        $q = '[' + "$UserName".Replace(']', ']]') + ']'
        [void]$b.Add(@"
-- [pimsupport] the Support app's STANDING read-only user (4a: before any admin right is made just-in-time)
DECLARE @sid VARBINARY(16) = CAST(CAST('$g' AS UNIQUEIDENTIFIER) AS VARBINARY(16)), @n SYSNAME, @q NVARCHAR(400);
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE sid = @sid)
    CREATE USER $q WITH SID = 0x$((@($g.ToByteArray()) | ForEach-Object { $_.ToString('X2') }) -join ''), TYPE = E;
SELECT @n = name FROM sys.database_principals WHERE sid = @sid;
IF @n IS NOT NULL AND IS_ROLEMEMBER(N'db_datareader', @n) = 0 BEGIN SET @q = N'ALTER ROLE [db_datareader] ADD MEMBER ' + QUOTENAME(@n) + N';'; EXEC sys.sp_executesql @q; END
"@)
    }
    foreach ($p in $procs) {
        $txt = (Get-PimSupportJitProcedureText -Name $p).Replace("'", "''")
        [void]$b.Add(@"
IF OBJECT_ID(N'[$s].[$p]') IS NULL OR ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'[$s].[$p]')), N'') NOT LIKE N'%$m%'
    EXEC sys.sp_executesql N'$txt';
"@)
    }
    $unsigned = @($procs | ForEach-Object { "NOT EXISTS (SELECT 1 FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(N'[$s].[$_]') AND c.name LIKE N'$pfx%')" }) -join "`n   OR "
    $signLines = @($procs | ForEach-Object { "    SET @s = N'ADD SIGNATURE TO [$s].[$_] BY CERTIFICATE ' + QUOTENAME(@cert) + N' WITH PASSWORD = ' + QUOTENAME(@pw, '''') + N';'; EXEC sys.sp_executesql @s;" }) -join "`n"
    [void]$b.Add(@"
IF $unsigned
BEGIN
    DECLARE @old SYSNAME, @s NVARCHAR(MAX);
    DECLARE oldc CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.certificates WHERE name LIKE N'$pfx%';
    OPEN oldc; FETCH NEXT FROM oldc INTO @old;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- an EARLIER signer of these procedures only (its certificate name): its user leaves db_owner and goes with it
        IF DATABASE_PRINCIPAL_ID(@old) IS NOT NULL
        BEGIN
            IF IS_ROLEMEMBER(N'db_owner', @old) = 1 BEGIN SET @s = N'ALTER ROLE [db_owner] DROP MEMBER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s; END
            SET @s = N'DROP USER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s;
        END
        SET @s = N'DROP CERTIFICATE ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s;
        FETCH NEXT FROM oldc INTO @old;
    END
    CLOSE oldc; DEALLOCATE oldc;
    DECLARE @cert SYSNAME = N'${pfx}_' + FORMAT(SYSUTCDATETIME(), 'yyyyMMddHHmmss');
    DECLARE @pw NVARCHAR(200) = CONVERT(NVARCHAR(36), NEWID()) + N'Pa1!' + CONVERT(NVARCHAR(36), NEWID());
    SET @s = N'CREATE CERTIFICATE ' + QUOTENAME(@cert) + N' ENCRYPTION BY PASSWORD = ' + QUOTENAME(@pw, '''')
           + N' WITH SUBJECT = ''PIM Manager support access procedure signer'', EXPIRY_DATE = ''20991231'';';
    EXEC sys.sp_executesql @s;
    SET @s = N'CREATE USER ' + QUOTENAME(@cert) + N' FROM CERTIFICATE ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    SET @s = N'ALTER ROLE [db_owner] ADD MEMBER ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
$signLines
    SET @s = N'ALTER CERTIFICATE ' + QUOTENAME(@cert) + N' REMOVE PRIVATE KEY;'; EXEC sys.sp_executesql @s;
END
"@)
    $deny = @($procs + @('Consent', 'GrantMarker') | ForEach-Object { "DENY ALTER ON OBJECT::[$s].[$_] TO [public];" }) + @("DENY ALTER ON SCHEMA::[$s] TO [public];")
    $exec = @(
        @('pim_engine', 'usp_SupportGrant'), @('pim_engine', 'usp_SupportRevoke'), @('pim_engine', 'usp_SupportState'),
        @('pim_web', 'usp_SupportRevoke'), @('pim_web', 'usp_SupportState')
    ) | ForEach-Object { "IF DATABASE_PRINCIPAL_ID(N'$($_[0])') IS NOT NULL GRANT EXECUTE ON OBJECT::[$s].[$($_[1])] TO [$($_[0])];" }
    [void]$b.Add((@($deny) + @($exec)) -join "`n")
    return @($b.ToArray())
}

function Get-PimSupportJitUninstallBatches {
    <#
      PURE. THE UNDO of the support-session step, run by the same OWNER-LEVEL sign-in. Batches, in order:
        1 REFUSED while any grant is open (close it first: usp_SupportRevoke @Mode = all) -- an undo never leaves a role
          that a marker would have taken back
        2 the denies taken back (ALTER on the procedures, the tables, the schema), the three procedures and the two tables
          dropped
        3 the signer: its certificate user leaves db_owner and goes, the certificate goes
        4 the schema, when nothing else is in it
      The Support app's user and its read-only access STAY (4a: the standing read-only path is never removed by this).
    #>
    $s = Get-PimSupportJitSchemaName; $pfx = Get-PimSupportJitSignerPrefix
    $objs = @(Get-PimSupportJitProcedureNames) + @('GrantMarker', 'Consent')
    $b = New-Object System.Collections.Generic.List[string]
    # every statement that names an object of the schema runs as dynamic SQL: on a database without them (a second undo, a
    # never-installed one) the batch must still compile -- real SQL (test VM 2026-11-02)
    [void]$b.Add(@"
DECLARE @open INT = 0;
IF OBJECT_ID(N'[$s].[GrantMarker]') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM [$s].[GrantMarker] WHERE RevokedUtc IS NULL;', N'@o INT OUTPUT', @o = @open OUTPUT;
IF @open > 0
    THROW 51121, N'uninstall: a time-limited support access is still open -- close it first (usp_SupportRevoke @Mode = all); nothing was changed.', 1;
"@)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($o in $objs) { $l.Add("IF OBJECT_ID(N'[$s].[$o]') IS NOT NULL EXEC(N'REVOKE ALTER ON OBJECT::[$s].[$o] FROM [public];');") }
    $l.Add("IF SCHEMA_ID(N'$s') IS NOT NULL EXEC(N'REVOKE ALTER ON SCHEMA::[$s] FROM [public];');")
    foreach ($p in @(Get-PimSupportJitProcedureNames)) { $l.Add("IF OBJECT_ID(N'[$s].[$p]') IS NOT NULL EXEC(N'DROP PROCEDURE [$s].[$p];');") }
    $l.Add("IF OBJECT_ID(N'[$s].[GrantMarker]') IS NOT NULL EXEC(N'DROP TABLE [$s].[GrantMarker];');")
    $l.Add("IF OBJECT_ID(N'[$s].[Consent]') IS NOT NULL EXEC(N'DROP TABLE [$s].[Consent];');")
    [void]$b.Add($l -join "`r`n")
    [void]$b.Add(@"
DECLARE @old SYSNAME, @x NVARCHAR(MAX);
DECLARE oldc CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.certificates WHERE name LIKE N'$pfx%';
OPEN oldc; FETCH NEXT FROM oldc INTO @old;
WHILE @@FETCH_STATUS = 0
BEGIN
    -- the SIGNER of these procedures only (its certificate name): its user leaves db_owner and goes with it
    IF DATABASE_PRINCIPAL_ID(@old) IS NOT NULL
    BEGIN
        IF IS_ROLEMEMBER(N'db_owner', @old) = 1 BEGIN SET @x = N'ALTER ROLE [db_owner] DROP MEMBER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @x; END
        SET @x = N'DROP USER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @x;
    END
    SET @x = N'DROP CERTIFICATE ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @x;
    FETCH NEXT FROM oldc INTO @old;
END
CLOSE oldc; DEALLOCATE oldc;
"@)
    [void]$b.Add("IF SCHEMA_ID(N'$s') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.objects WHERE schema_id = SCHEMA_ID(N'$s')) EXEC(N'DROP SCHEMA [$s];');")
    return @($b.ToArray())
}

function Get-PimSupportJitInstallFactsSql {
    # PURE. ONE read-only JSON scalar: is the step in place? (procedures current + signed by the signer, the private key
    # removed, the signer a db_owner member, ALTER denied to public on each, the consent level, the read-only user).
    $s = Get-PimSupportJitSchemaName; $m = Get-PimSupportJitVersionMark; $pfx = Get-PimSupportJitSignerPrefix
    $per = @(Get-PimSupportJitProcedureNames | ForEach-Object {
        "(SELECT N'$_' AS name, CASE WHEN ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'[$s].[$_]')), N'') LIKE N'%$m%' THEN 1 ELSE 0 END AS [current]," +
        " (SELECT TOP 1 c.name FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(N'[$s].[$_]') AND c.name LIKE N'$pfx%') AS signer," +
        " (SELECT TOP 1 CASE WHEN c.pvt_key_encryption_type = 'NA' THEN 1 ELSE 0 END FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(N'[$s].[$_]')) AS privateKeyRemoved," +
        " (SELECT TOP 1 CASE WHEN IS_ROLEMEMBER(N'db_owner', c.name) = 1 THEN 1 ELSE 0 END FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(N'[$s].[$_]')) AS signerOwner," +
        " CASE WHEN EXISTS (SELECT 1 FROM sys.database_permissions dp WHERE dp.class = 1 AND dp.major_id = OBJECT_ID(N'[$s].[$_]') AND dp.permission_name = N'ALTER' AND dp.state = 'D' AND dp.grantee_principal_id = 0) THEN 1 ELSE 0 END AS alterDenied" +
        " FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)"
    })
    return ("SELECT (SELECT ISNULL((SELECT ConsentLevel FROM [$s].[Consent] WHERE Id = 1), N'none') AS consented," +
            " (SELECT COUNT(*) FROM sys.objects o WHERE o.schema_id = SCHEMA_ID(N'$s') AND o.type IN ('U', 'V', 'P', 'PC', 'FN', 'IF', 'TF', 'TR', 'SN') AND o.name NOT IN (N'Consent', N'GrantMarker', N'usp_SupportGrant', N'usp_SupportRevoke', N'usp_SupportState')) AS foreignObjects," +
            " JSON_QUERY(N'[' + " + ($per -join " + N',' + ") + " + N']') AS procedures FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS result")
}

# ======================================================================================================== the callers
function ConvertFrom-PimSupportJitAnswer {
    # PURE. A procedure's ONE JSON scalar -> an object. Anything else THROWS (no answer is never "nothing open").
    param([AllowNull()]$Raw)
    $t = "$Raw".Trim()
    if (-not $t.StartsWith('{')) { throw 'the database did not answer the support access procedure' }
    return ($t | ConvertFrom-Json)
}

function Get-PimSupportJitFirstLine { param($e) return (("$($e.Exception.Message)" -split "`n")[0]).Trim() }

function Test-PimSupportJitNotInstalled {
    # PURE. Is this error the procedure (or its schema) missing on this install -- the support-session step not run yet?
    param([AllowNull()][string]$Message)
    return [bool]("$Message" -match '(?i)Could not find stored procedure|Msg 2812|Invalid object name .pimsupport')
}

function Invoke-PimSupportJitGrant {
    <#
      Open (or extend) the support access through the SIGNED procedure. Never throws. -Level read | owner, -Hours 1-24.
      Returns { ok; level; requested; consented; grantId; untilUtc; rolesAdded; extended; preExisting; readOnly; inOwner;
      installed; problem }. The procedure decides the level (the LOWER of requested and consented); nothing here can widen it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [ValidateSet('read', 'owner')][string]$Level = 'owner', [int]$Hours = (Get-PimSupportJitDefaultHours),
          [string]$Reason = '', [string]$Ticket = '', [string]$OpenedBy = '')
    $o = [ordered]@{ ok = $false; level = ''; requested = $Level; consented = ''; grantId = ''; untilUtc = ''; rolesAdded = 0; extended = $false; preExisting = $false
                     readOnly = $false; inOwner = $false; installed = $true; problem = '' }
    try {
        if ($Hours -lt 1 -or $Hours -gt (Get-PimSupportJitMaxHours)) { $o.problem = "the support access may last 1 to $(Get-PimSupportJitMaxHours) hours -- nothing was changed"; return [pscustomobject]$o }
        $s = Get-PimSupportJitSchemaName
        $q = "EXEC [$s].[usp_SupportGrant] @Level = N'$Level', @Hours = $([int]$Hours), @Reason = $(ConvertTo-PimSupportJitSqlText (ConvertTo-PimSupportJitText $Reason 120)), @Ticket = $(ConvertTo-PimSupportJitSqlText (ConvertTo-PimSupportJitText $Ticket 40)), @OpenedBy = $(ConvertTo-PimSupportJitSqlText (ConvertTo-PimSupportJitText $OpenedBy 120));"
        $a = ConvertFrom-PimSupportJitAnswer (& $Sql $q)
        $o.level = "$($a.level)"; $o.consented = "$($a.consented)"; $o.grantId = "$($a.grantId)"
        $u = ConvertFrom-PimSupportJitUtc $a.untilUtc; $o.untilUtc = if ($u) { Format-PimSupportJitUtc -Utc $u } else { '' }
        $o.rolesAdded = [int]$a.rolesAdded; $o.extended = ([int]$a.extended -eq 1); $o.preExisting = ([int]$a.preExisting -eq 1)
        $o.readOnly = ([int]$a.readOnly -eq 1); $o.inOwner = ([int]$a.inOwner -eq 1)
        $why = @()
        if (-not $o.readOnly) { $why += "the Support app's user is not in $(Get-PimSupportJitReadOnlyRole)" }
        if ($o.level -eq 'owner' -and -not $o.inOwner) { $why += "the Support app's user is not in $(Get-PimSupportJitAdminRole)" }
        if ($o.level -eq 'owner' -and -not $o.untilUtc) { $why += 'no end is recorded for the admin access' }
        if ($why.Count) { $o.problem = "read-back: $($why -join '; ')" } else { $o.ok = $true }
    } catch {
        $o.problem = Get-PimSupportJitFirstLine $_
        if (Test-PimSupportJitNotInstalled $o.problem) { $o.installed = $false; $o.problem = "$(Get-PimSupportJitNotSetUpText) (the support-session step sets it up) -- nothing was changed" }
    }
    return [pscustomobject]$o
}

function Invoke-PimSupportJitRevoke {
    <#
      Close the support access through the SIGNED procedure: -Mode expired (THE SWEEP: every marker past its end) or all
      (support closed: every open marker). Never throws. -Source names who did it (job | heartbeat | manager | script).
      -Audit { param($Record) } gets ONE record per marker closed or failed: { action = support.access.revoke |
      support.access.close; target; source; role; grantId; expiresUtc; preExisting; roleRemoved; result ok|failed; detail }.
      LOUD (Write-Warning + problems): a marker that could not be closed, a call that failed, an audit that could not be
      written. 'Not set up' (the procedures missing on this install) is NOT loud: no grant can exist where they do not -- it is
      a plain state (Get-PimSupportJitNotSetUpText), and only a real failure once they are installed is loud.
      Returns { ok; installed; mode; found; revoked; failed; sessionsEnded; open; jitOpen; jitUntil; problems }.
    #>
    [CmdletBinding()]
    param([AllowNull()][scriptblock]$Sql, [ValidateSet('expired', 'all')][string]$Mode = 'expired', [string]$Source = 'unknown', [AllowNull()][scriptblock]$Audit = $null, [switch]$Quiet)
    $problems = New-Object System.Collections.Generic.List[string]
    $res = [ordered]@{ ok = $false; installed = $null; mode = $Mode; found = 0; revoked = @(); failed = @(); sessionsEnded = 0; open = @(); jitOpen = $null; jitUntil = ''; problems = @() }
    $loud = { param([string]$m) $problems.Add($m); Write-Warning "[support-access] $m" }
    $finish = { $res.problems = @($problems.ToArray()); $res.ok = [bool]($null -ne $res.installed -and -not @($res.failed).Count -and -not $problems.Count); return [pscustomobject]$res }
    if (-not $Sql) { & $loud "no database session in this $Source run -- the support access was not checked and an ended grant, if any, was NOT taken back"; return (& $finish) }
    $src = ConvertTo-PimSupportJitText -Text $Source -Max 20
    $a = $null
    try { $a = ConvertFrom-PimSupportJitAnswer (& $Sql "EXEC [$(Get-PimSupportJitSchemaName)].[usp_SupportRevoke] @Mode = N'$Mode', @Source = $(ConvertTo-PimSupportJitSqlText $src);") }
    catch {
        $m = Get-PimSupportJitFirstLine $_
        if (Test-PimSupportJitNotInstalled $m) { $res.installed = $false; $res.jitOpen = $false; return (& $finish) }
        & $loud "the support access could not be closed in this $Source run ($m) -- an ended grant, if any, was NOT taken back; every run tries again"
        return (& $finish)
    }
    $res.installed = $true
    $act = if ($Mode -eq 'all') { 'support.access.close' } else { 'support.access.revoke' }
    $fmt = { param($v) $d = ConvertFrom-PimSupportJitUtc $v; if ($d) { Format-PimSupportJitUtc -Utc $d } else { '' } }
    $res.found = [int]$a.found; $res.sessionsEnded = [int]$a.sessionsEnded
    $rv = @(@($a.revoked) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ grantId = "$($_.grantId)"; role = "$($_.role)"; userName = "$($_.userName)"; expiresUtc = (& $fmt $_.expiresUtc); preExisting = ([int]$_.preExisting -eq 1); roleRemoved = ([int]$_.removed -eq 1) } })
    $fl = @(@($a.failed) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ grantId = "$($_.grantId)"; role = "$($_.role)"; userName = "$($_.userName)"; expiresUtc = (& $fmt $_.expiresUtc); error = "$($_.error)" } })
    $op = @(@($a.open) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ role = "$($_.role)"; expiresUtc = (& $fmt $_.expiresUtc) } })
    $res.revoked = $rv; $res.failed = $fl; $res.open = $op
    foreach ($r in $rv) {
        $rec = [pscustomobject][ordered]@{ action = $act; target = "database user [$($r.userName)]"; source = $src; role = $r.role; grantId = $r.grantId; expiresUtc = $r.expiresUtc
                                          preExisting = $r.preExisting; roleRemoved = $r.roleRemoved; sessionsEnded = $res.sessionsEnded; result = 'ok'; detail = '' }
        if ($Audit) { try { & $Audit $rec } catch { & $loud "the audit record of the revoke of $($r.role) for database user [$($r.userName)] could not be written: $(Get-PimSupportJitFirstLine $_)" } }
        if (-not $Quiet) { Write-Host "  [support-access] closed: $($r.role) of database user [$($r.userName)]$(if ($r.preExisting) { ' (held before the grant: kept)' } else { ' taken back' }); the read-only access stays" -ForegroundColor Green }
    }
    foreach ($f in $fl) {
        $rec = [pscustomobject][ordered]@{ action = $act; target = "database user [$($f.userName)]"; source = $src; role = $f.role; grantId = $f.grantId; expiresUtc = $f.expiresUtc
                                          preExisting = $null; roleRemoved = $false; sessionsEnded = $res.sessionsEnded; result = 'failed'; detail = $f.error }
        if ($Audit) { try { & $Audit $rec } catch { & $loud "the audit record of the failed revoke for database user [$($f.userName)] could not be written: $(Get-PimSupportJitFirstLine $_)" } }
        & $loud "$($f.role) of database user [$($f.userName)] (end $($f.expiresUtc)) could NOT be taken back by this $Source run ($($f.error)) -- THE ACCESS IS STILL IN PLACE; every run tries again"
    }
    # the sessions: a role taken back while the Support app's session stays open is NOT ended in that session (SQL Server
    # keeps a session's role memberships until it reconnects) -- so sessions that could not be seen or ended are LOUD
    $res.sessionsNotEnded = 0; $res.sessionsChecked = $null
    $res.endedSessions = @(@($a.endedSessions) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ id = [int]$_.id; login = "$($_.login)"; originalLogin = "$($_.originalLogin)" } })
    if ($a.PSObject.Properties['sessionsNotEnded']) { $res.sessionsNotEnded = [int]$a.sessionsNotEnded }
    if ($a.PSObject.Properties['sessionsChecked']) { $res.sessionsChecked = ([int]$a.sessionsChecked -eq 1) }
    if (@($rv | Where-Object { $_.roleRemoved }).Count) {
        if ($res.sessionsChecked -eq $false) { & $loud "this $Source run could not see the Support app's open database sessions (no right to see other sessions) -- a session opened before the end may keep the admin right until it reconnects" }
        if ($res.sessionsNotEnded -gt 0) { & $loud "$($res.sessionsNotEnded) open database session(s) of the Support app could NOT be ended in this $Source run ($("$($a.sessionError)".Trim())) -- they may keep the admin right until they reconnect" }
    }
    $still = @(@($op | ForEach-Object { $_.expiresUtc }) | Where-Object { $_ } | Sort-Object)
    $res.jitOpen = [bool]($op.Count -gt 0)
    $res.jitUntil = if ($still.Count) { "$($still[-1])" } else { '' }
    return (& $finish)
}

function Invoke-PimSupportJitSweep {
    <# THE SWEEP: Invoke-PimSupportJitRevoke -Mode expired. Every regular runner calls this (job, heartbeat, Manager). #>
    [CmdletBinding()]
    param([AllowNull()][scriptblock]$Sql, [string]$Source = 'unknown', [AllowNull()][scriptblock]$Audit = $null, [switch]$Quiet)
    return (Invoke-PimSupportJitRevoke -Sql $Sql -Mode 'expired' -Source $Source -Audit $Audit -Quiet:$Quiet)
}

function Get-PimSupportJitState {
    <#
      The state through the SIGNED read procedure (the engine / web identities may not see other users themselves). Never
      throws. Returns { installed; read; consented; readOnly; inOwner; jitOpen; jitUntil; openMarkers; expiredOpen; halfDone;
      opened24h; closed24h; problem }. read = $false + problem: not determined (never a guess).
    #>
    param([AllowNull()][scriptblock]$Sql)
    $o = [ordered]@{ installed = $null; read = $false; consented = ''; readOnly = $null; inOwner = $null; jitOpen = $null; jitUntil = ''; openMarkers = 0; expiredOpen = 0
                     halfDone = 0; opened24h = 0; closed24h = 0; foreignObjects = 0; problem = '' }
    if (-not $Sql) { $o.problem = 'no database session'; return [pscustomobject]$o }
    try {
        $a = ConvertFrom-PimSupportJitAnswer (& $Sql "EXEC [$(Get-PimSupportJitSchemaName)].[usp_SupportState];")
        $o.installed = $true; $o.read = $true; $o.consented = "$($a.consented)"
        $o.readOnly = ([int]$a.readOnly -eq 1); $o.inOwner = ([int]$a.inOwner -eq 1)
        $o.openMarkers = [int]$a.openMarkers; $o.expiredOpen = [int]$a.expiredOpen; $o.halfDone = [int]$a.halfDone
        $o.opened24h = [int]$a.opened24h; $o.closed24h = [int]$a.closed24h
        if ($a.PSObject.Properties['foreignObjects']) { $o.foreignObjects = [int]$a.foreignObjects }
        $o.jitOpen = ($o.openMarkers -gt 0)
        $u = ConvertFrom-PimSupportJitUtc $a.jitUntil; $o.jitUntil = if ($u -and $o.jitOpen) { Format-PimSupportJitUtc -Utc $u } else { '' }
    } catch {
        $m = Get-PimSupportJitFirstLine $_
        if (Test-PimSupportJitNotInstalled $m) { $o.installed = $false; $o.jitOpen = $false; $o.problem = (Get-PimSupportJitNotSetUpText) } else { $o.problem = $m }
    }
    return [pscustomobject]$o
}

function Get-PimSupportJitStateSummary {
    # PURE. One line for a run record / the uplink detail: what was opened, closed, swept, and what needs a look.
    param([AllowNull()]$Sweep, [AllowNull()]$State)
    $p = New-Object System.Collections.Generic.List[string]
    if (($Sweep -and $Sweep.installed -eq $false) -or ($State -and $State.installed -eq $false)) { return "support access: $(Get-PimSupportJitNotSetUpText) (standing access as before)" }
    if ($Sweep) { $p.Add("swept $(@($Sweep.revoked).Count)$(if (@($Sweep.failed).Count) { ", FAILED $(@($Sweep.failed).Count)" })") }
    if ($State -and $State.read) {
        $p.Add("opened $($State.opened24h) / closed $($State.closed24h) in 24 h")
        $p.Add($(if ($State.jitOpen) { "open until $($State.jitUntil)" } else { 'none open' }))
        if ($State.halfDone) { $p.Add("$($State.halfDone) half-done") }
        if ($State.foreignObjects) { $p.Add("$($State.foreignObjects) UNEXPECTED object(s) in the support schema") }
        if ($State.consented -and $State.consented -ne 'none' -and -not $State.readOnly) { $p.Add('the read-only access is MISSING') }
    }
    return ('support access: ' + ($p -join '; '))
}

function Test-PimSupportJitNeedsLook {
    # PURE. Does the sweep / state need a person (an uplink WARNING)? A failed revoke, an error, a half-done grant, an open
    # grant past its end, or a consenting install without its read-only access (4a).
    param([AllowNull()]$Sweep, [AllowNull()]$State)
    if ($Sweep -and (@($Sweep.failed).Count -or @($Sweep.problems).Count)) { return $true }
    if ($State -and $State.read -and ($State.halfDone -gt 0 -or $State.expiredOpen -gt 0 -or $State.foreignObjects -gt 0)) { return $true }
    if ($State -and $State.read -and $State.consented -and $State.consented -ne 'none' -and -not $State.readOnly) { return $true }
    return $false
}

function Invoke-PimSupportJitInstall {
    <#
      THE SUPPORT-SESSION STEP: run Get-PimSupportJitInstallBatches through -Sql (an OWNER-LEVEL sign-in) and READ IT BACK
      (Get-PimSupportJitInstallFactsSql). Never throws. Returns { ok; consented; procedures; problems }. ok only when every
      procedure is current, signed by the signer, its private key removed, the signer a db_owner member and ALTER denied.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$SupportAppId, [Parameter(Mandatory)][ValidateSet('none', 'read', 'owner')][string]$ConsentLevel,
          [string]$UserName = 'invardia-support', [string]$SetBy = '')
    $problems = New-Object System.Collections.Generic.List[string]
    $o = [ordered]@{ ok = $false; consented = ''; procedures = @(); problems = @() }
    try {
        $i = 0
        foreach ($bt in @(Get-PimSupportJitInstallBatches -SupportAppId $SupportAppId -ConsentLevel $ConsentLevel -UserName $UserName -SetBy $SetBy)) {
            $i++
            try { [void](& $Sql $bt) } catch { $problems.Add("step $i of the installation was refused: $(Get-PimSupportJitFirstLine $_)"); break }
        }
        $f = ConvertFrom-PimSupportJitAnswer (& $Sql (Get-PimSupportJitInstallFactsSql))
        $o.consented = "$($f.consented)"
        $o.procedures = @(@($f.procedures) | Where-Object { $_ })
        foreach ($n in @(Get-PimSupportJitProcedureNames)) {
            $p = @($o.procedures | Where-Object { "$($_.name)" -eq $n }) | Select-Object -First 1
            if (-not $p) { $problems.Add("$n is not there"); continue }
            if ([int]$p.current -ne 1) { $problems.Add("$n is not this version") }
            if (-not "$($p.signer)".StartsWith((Get-PimSupportJitSignerPrefix))) { $problems.Add("$n is not signed") }
            if ([int]$p.privateKeyRemoved -ne 1) { $problems.Add("the private key of the signer of $n is still there") }
            if ([int]$p.signerOwner -ne 1) { $problems.Add("the signer of $n is not a db_owner member") }
            if ([int]$p.alterDenied -ne 1) { $problems.Add("ALTER on $n is not denied") }
        }
        if ($o.consented -ne $ConsentLevel) { $problems.Add("the consent reads back as '$($o.consented)', not '$ConsentLevel'") }
        if ($f.PSObject.Properties['foreignObjects'] -and [int]$f.foreignObjects -gt 0) { $problems.Add("$([int]$f.foreignObjects) object(s) in the support schema that this step did not make -- an owner must look at and remove them") }
    } catch { $problems.Add((Get-PimSupportJitFirstLine $_)) }
    $o.problems = @($problems.ToArray()); $o.ok = ($problems.Count -eq 0)
    return [pscustomobject]$o
}
