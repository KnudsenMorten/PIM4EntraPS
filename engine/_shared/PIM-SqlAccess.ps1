# =================================================================================================
# PIM-SqlAccess.ps1 -- least-privilege database access per component (framework §12.23 P2-P4, P9;
# PIM REQUIREMENTS 100.156). PURE: T-SQL text only -- no connection, no token -- so every decision is
# testable offline.
#
# THE MODEL
#   * One custom database role per component (pim_web, pim_engine, pim_updater, pim_asbuilt, pim_publish,
#     pim_downlink, pim_hybrid). Get-PimSqlAccessCatalog is the ONE list of what each role may do.
#   * ONE certificate-signed procedure, pim.usp_ApplyAccess, applies grants / revokes / roles / users -- and
#     NOTHING else: the role must be a pim_<name> custom role, the permission SELECT / INSERT / UPDATE / DELETE /
#     EXECUTE, the target an object or schema in pim / platform / pimdemo, never the procedure itself, never a
#     fixed db_* role. The updater may only EXECUTE it; it holds no security right of its own.
#   * The procedure is FROZEN (P9): its rules are general enough for every future release (a new role name only
#     has to match pim_<letters>), because a no-contact install has nobody who could re-sign a changed one.
#   * The certificate lives INSIDE the database: created once by an admin run (setup / the Support-app cut-over),
#     EXPIRY 2099, the private key removed right after signing -- nothing stored, rotated or maintained. Altering
#     the procedure drops the signature, so a tampered procedure has no rights at all.
#
# WHO RUNS WHAT
#   Get-PimSqlAccessAdminBatches   ONCE per install, by an admin (setup / Support app). Idempotent.
#   Get-PimSqlAccessApplyBatches   EVERY update, by the updater's own contained user -- no admin needed.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary.
# =================================================================================================

Set-StrictMode -Off

$script:PimSqlAccessMarker = 'pim-access v2'
$script:PimSqlAccessSchemas = @('pim', 'platform', 'pimdemo')
$script:PimSqlAccessPermissions = @('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXECUTE')

function Get-PimSqlAccessCatalog {
    <#
      The ONE grant list per component role. Each grant: perm (one of the five), on ('SCHEMA::<s>' or '<schema>.<object>').
      Schema-level where the component owns the data (P3), object-level elsewhere. A missing object / schema is skipped
      when applied (an install without the optional table still converges).
      Step A keeps the engine / web / updater at schema level on pim; the per-component views over the generic tables
      (pim.Settings / pim.Rows) are step D (100.156).
    #>
    [CmdletBinding()] param()
    $crud = @('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    $g = { param([string[]]$Perms, [string]$On) foreach ($p in $Perms) { [pscustomobject]@{ perm = $p; on = $On } } }
    return [ordered]@{
        pim_web = @(
            & $g $crud 'SCHEMA::pim'
            & $g @('SELECT') 'SCHEMA::platform'
            & $g @('INSERT', 'UPDATE') 'platform.Tenants'      # /api/msp/tenants (PIM-MspBuild)
            & $g $crud 'SCHEMA::pimdemo'                         # demo mode only (PIM-DemoData)
        )
        pim_engine = @(
            & $g $crud 'SCHEMA::pim'
            & $g @('SELECT') 'SCHEMA::platform'
        )
        pim_updater = @(
            & $g $crud 'SCHEMA::pim'
            & $g @('SELECT', 'INSERT', 'UPDATE') 'SCHEMA::platform'   # Initialize-PimSqlStore ring-order migration
        )
        pim_asbuilt = @(
            & $g @('SELECT') 'pim.vw_AsBuiltSettings'
        )
        pim_publish = @(
            & $g @('SELECT') 'pim.CentralAdmins'
            & $g @('SELECT') 'pim.Rows'
            & $g @('SELECT') 'pim.TenantRoleProjection'
            & $g @('SELECT') 'platform.Tenants'
            & $g @('SELECT') 'pim.vw_PublishJobControl'
            & $g @('SELECT', 'INSERT', 'UPDATE') 'pim.vw_PublishJobLastRun'
        )
        pim_downlink = @(
            & $g @('SELECT', 'INSERT', 'UPDATE') 'pim.Settings'
        )
        pim_hybrid = @(
            & $g @('SELECT', 'INSERT', 'UPDATE') 'pim.Settings'
            & $g @('SELECT') 'pim.Rows'
        )
    }
}

function Test-PimSqlAccessRoleName {
    <# The procedure's own rule, mirrored: pim_ + 2-30 lower-case letters. Never a fixed db_* role. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Role)
    return ("$Role" -cmatch '^pim_[a-z]{2,30}$')
}

function Test-PimSqlAccessGrant {
    <# PURE mirror of the procedure's checks, so a bad catalog entry fails offline, not in a customer database. #>
    [CmdletBinding()] param([string]$Role, [string]$Perm, [string]$On)
    $p = New-Object System.Collections.Generic.List[string]
    if (-not (Test-PimSqlAccessRoleName -Role $Role)) { [void]$p.Add("role '$Role' is not pim_<letters>") }
    if ("$Perm" -notin $script:PimSqlAccessPermissions) { [void]$p.Add("permission '$Perm' is not one of $($script:PimSqlAccessPermissions -join ', ')") }
    if ("$On" -match '^SCHEMA::([A-Za-z_]+)$') {
        if ($Matches[1] -notin $script:PimSqlAccessSchemas) { [void]$p.Add("schema '$($Matches[1])' is not a product schema") }
        if ("$Perm" -eq 'EXECUTE') { [void]$p.Add('EXECUTE on a whole schema is refused (it would reach the access procedure)') }
    } elseif ("$On" -match '^([A-Za-z_]+)\.([A-Za-z_][A-Za-z0-9_]*)$') {
        if ($Matches[1] -notin $script:PimSqlAccessSchemas) { [void]$p.Add("schema '$($Matches[1])' is not a product schema") }
        if ($Matches[2] -eq 'usp_ApplyAccess') { [void]$p.Add('the access procedure itself is never granted through itself') }
    } else { [void]$p.Add("target '$On' is neither SCHEMA::<schema> nor <schema>.<object>") }
    return [pscustomobject]@{ ok = ($p.Count -eq 0); problems = @($p.ToArray()) }
}

function Get-PimSqlAccessProcedureText {
    <#
      The frozen procedure. Every rule is checked INSIDE it (a signed module must not trust its caller); names are
      QUOTENAME'd; dynamic SQL runs under the signature. The marker line lets the admin batch tell whether the deployed
      text is this version without comparing whitespace.
    #>
    [CmdletBinding()] param()
    $m = $script:PimSqlAccessMarker
    return @"
CREATE OR ALTER PROCEDURE [pim].[usp_ApplyAccess]
    @Action     NVARCHAR(10),
    @Role       SYSNAME = NULL,
    @Permission NVARCHAR(20) = NULL,
    @Target     NVARCHAR(300) = NULL,
    @UserName   SYSNAME = NULL,
    @AppId      UNIQUEIDENTIFIER = NULL,
    @What       NVARCHAR(10) = NULL
AS
BEGIN
    -- $m -- framework 12.23 P4/P9. FROZEN: general rules only; altering this procedure drops its signature.
    SET NOCOUNT ON; SET XACT_ABORT ON;
    DECLARE @s NVARCHAR(MAX), @sch SYSNAME, @obj SYSNAME, @t NVARCHAR(400), @sid VARBINARY(16);
    -- v2 (SI's real-SQL finding 1): a ddladmin-only caller cannot SEE grants or certificates, so the state is read
    -- HERE, under the signature. Read-only: facts (procedure + signer) or the grants held by pim_* roles.
    IF @Action = N'state'
    BEGIN
        IF @What = N'facts'
            SELECT 1 AS procExists, 1 AS procCurrent,
              (SELECT TOP 1 c.name FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
                 WHERE cp.major_id = @@PROCID) AS signer,
              (SELECT TOP 1 c.expiry_date FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
                 WHERE cp.major_id = @@PROCID) AS signerExpiry,
              (SELECT TOP 1 CASE WHEN c.pvt_key_encryption_type = 'NA' THEN 1 ELSE 0 END FROM sys.crypt_properties cp
                 JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = @@PROCID) AS privateKeyRemoved;
        ELSE IF @What = N'grants'
            SELECT r.name AS role, dp.permission_name AS perm,
              CASE dp.class WHEN 3 THEN N'SCHEMA::' + SCHEMA_NAME(dp.major_id)
                            WHEN 1 THEN OBJECT_SCHEMA_NAME(dp.major_id) + N'.' + OBJECT_NAME(dp.major_id) END AS [on]
            FROM sys.database_permissions dp JOIN sys.database_principals r ON r.principal_id = dp.grantee_principal_id
            WHERE r.type = 'R' AND r.is_fixed_role = 0 AND r.name LIKE N'pim[_]%' AND dp.state IN ('G', 'W') AND dp.class IN (1, 3);
        ELSE THROW 51011, N'usp_ApplyAccess: state needs @What = facts or grants.', 1;
        RETURN;
    END
    IF @Role IS NULL OR LEN(@Role) < 6 OR LEN(@Role) > 34 OR LEFT(@Role, 4) COLLATE Latin1_General_BIN2 <> N'pim_'
       OR SUBSTRING(@Role, 5, 30) COLLATE Latin1_General_BIN2 LIKE N'%[^a-z]%'
        THROW 51001, N'usp_ApplyAccess: the role must be pim_<lower-case letters>.', 1;
    IF @Action = N'role'
    BEGIN
        -- v2 (SI's real-SQL finding 2): AUTHORIZATION [dbo] needs IMPERSONATE on dbo, which the signer never gets. A role
        -- created HERE is owned by the signer; the admin run creates every catalog role owned by dbo, and moves any
        -- signer-owned role to dbo before it ever drops an old signer.
        IF DATABASE_PRINCIPAL_ID(@Role) IS NULL
        BEGIN
            SET @s = N'CREATE ROLE ' + QUOTENAME(@Role) + N';';
            EXEC sys.sp_executesql @s;
        END
        RETURN;
    END
    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @Role AND type = 'R' AND is_fixed_role = 0)
        THROW 51002, N'usp_ApplyAccess: the role does not exist (run @Action = role first).', 1;
    IF @Action IN (N'grant', N'revoke')
    BEGIN
        IF @Permission IS NULL OR @Permission NOT IN (N'SELECT', N'INSERT', N'UPDATE', N'DELETE', N'EXECUTE')
            THROW 51003, N'usp_ApplyAccess: the permission must be SELECT, INSERT, UPDATE, DELETE or EXECUTE.', 1;
        IF @Target LIKE N'SCHEMA::%'
        BEGIN
            SET @sch = SUBSTRING(@Target, 9, 128);
            IF @sch NOT IN (N'pim', N'platform', N'pimdemo') THROW 51004, N'usp_ApplyAccess: not a product schema.', 1;
            IF @Permission = N'EXECUTE' THROW 51005, N'usp_ApplyAccess: EXECUTE on a whole schema is refused.', 1;
            IF SCHEMA_ID(@sch) IS NULL RETURN;   -- optional schema not present: nothing to grant
            SET @t = N'SCHEMA::' + QUOTENAME(@sch);
        END
        ELSE
        BEGIN
            SET @sch = PARSENAME(@Target, 2); SET @obj = PARSENAME(@Target, 1);
            IF @sch IS NULL OR @obj IS NULL OR PARSENAME(@Target, 3) IS NOT NULL
                THROW 51006, N'usp_ApplyAccess: the target must be schema.object or SCHEMA::schema.', 1;
            IF @sch NOT IN (N'pim', N'platform', N'pimdemo') THROW 51004, N'usp_ApplyAccess: not a product schema.', 1;
            IF @obj = N'usp_ApplyAccess' THROW 51007, N'usp_ApplyAccess: never granted through itself.', 1;
            IF OBJECT_ID(QUOTENAME(@sch) + N'.' + QUOTENAME(@obj)) IS NULL RETURN;   -- optional object not present
            SET @t = N'OBJECT::' + QUOTENAME(@sch) + N'.' + QUOTENAME(@obj);
        END
        IF @Action = N'grant' SET @s = N'GRANT ' + @Permission + N' ON ' + @t + N' TO ' + QUOTENAME(@Role) + N';';
        ELSE SET @s = N'REVOKE ' + @Permission + N' ON ' + @t + N' FROM ' + QUOTENAME(@Role) + N';';
        EXEC sys.sp_executesql @s;
        RETURN;
    END
    IF @Action = N'user'
    BEGIN
        IF @UserName IS NULL OR @AppId IS NULL OR LEN(@UserName) > 128 OR @UserName LIKE N'%[^A-Za-z0-9._@ -]%'
            THROW 51008, N'usp_ApplyAccess: a user needs a safe name and the application (client) id.', 1;
        SET @sid = CAST(@AppId AS VARBINARY(16));
        IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @UserName AND (sid <> @sid OR type <> 'E'))
            THROW 51009, N'usp_ApplyAccess: another principal already has that name -- an admin must resolve it.', 1;
        IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @UserName)
        BEGIN
            SET @s = N'CREATE USER ' + QUOTENAME(@UserName) + N' WITH SID = ' + CONVERT(NVARCHAR(40), @sid, 1) + N', TYPE = E;';
            EXEC sys.sp_executesql @s;
        END
        IF IS_ROLEMEMBER(@Role, @UserName) = 0
        BEGIN
            SET @s = N'ALTER ROLE ' + QUOTENAME(@Role) + N' ADD MEMBER ' + QUOTENAME(@UserName) + N';';
            EXEC sys.sp_executesql @s;
        END
        RETURN;
    END;
    THROW 51010, N'usp_ApplyAccess: unknown action (role, grant, revoke, user).', 1;
END
"@
}

function Get-PimSqlAccessAdminBatches {
    <#
      ONCE per install, by an ADMIN (setup, or the Support-app cut-over). Idempotent: re-running changes nothing when the
      deployed procedure is this version and signed. Batches, in order:
        1 the THREE product schemas pim / platform / pimdemo, dbo-owned (2.4.644: all of them, even empty -- the procedure
          can only ever grant on these three, so once they all exist at signing no product schema can come "later")
        2 the procedure (only when missing or another version -- re-creating it would drop the signature)
        3 sign it when unsigned: a NEW in-database certificate (EXPIRY 2099, random password generated inside SQL and
          never returned), a user from it with exactly the rights the procedure exercises, ADD SIGNATURE, then the
          private key REMOVED. Earlier signer certificates / users are dropped first. Then, on EVERY admin run (2.4.644
          TOP-UP), the CURRENT signer gets CONTROL on each product schema -- an install signed by an older release before
          one of the schemas existed is repaired by its next admin run, without a re-sign.
        4 the updater's role + EXECUTE on the procedure (the only security-related grant the updater ever holds)
        5 -UpdaterUserName / -UpdaterAppId given: the updater's contained user, in pim_updater + db_ddladmin
    #>
    [CmdletBinding()]
    param([string]$UpdaterUserName = '', [string]$UpdaterAppId = '')
    $m = $script:PimSqlAccessMarker
    $proc = (Get-PimSqlAccessProcedureText).Replace("'", "''")
    $b = New-Object System.Collections.Generic.List[string]
    # 2.4.644 (live 2026-10-16, internal: pimdemo created AFTER run 1 signed -> 4 of 47 statements refused): every product
    # schema exists BEFORE the signing, so the signer gets CONTROL on all three (the cut-over too, which has no prerequisites).
    [void]$b.Add((@('pim', 'platform', 'pimdemo' | ForEach-Object { "IF SCHEMA_ID(N'$_') IS NULL EXEC(N'CREATE SCHEMA [$_] AUTHORIZATION [dbo];');" }) -join "`n"))
    [void]$b.Add(@"
IF OBJECT_ID(N'pim.usp_ApplyAccess') IS NULL
   OR ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'pim.usp_ApplyAccess')), N'') NOT LIKE N'%$m%'
    EXEC sys.sp_executesql N'$proc';
"@)
    [void]$b.Add(@"
IF NOT EXISTS (SELECT 1 FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
               WHERE cp.major_id = OBJECT_ID(N'pim.usp_ApplyAccess') AND c.name LIKE N'pim_access_signer%')
BEGIN
    DECLARE @old SYSNAME, @s NVARCHAR(MAX);
    DECLARE oldc CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.certificates WHERE name LIKE N'pim_access_signer%';
    OPEN oldc; FETCH NEXT FROM oldc INTO @old;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- v2: a role the procedure created is owned by its signer -- hand it to dbo first, or the DROP USER fails.
        SET @s = NULL;
        SELECT @s = STRING_AGG(CONVERT(NVARCHAR(MAX), N'ALTER AUTHORIZATION ON ROLE::' + QUOTENAME(r.name) + N' TO [dbo];'), N' ')
          FROM sys.database_principals r WHERE r.type = 'R' AND r.owning_principal_id = DATABASE_PRINCIPAL_ID(@old);
        IF @s IS NOT NULL EXEC sys.sp_executesql @s;
        IF DATABASE_PRINCIPAL_ID(@old) IS NOT NULL BEGIN SET @s = N'DROP USER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s; END
        SET @s = N'DROP CERTIFICATE ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s;
        FETCH NEXT FROM oldc INTO @old;
    END
    CLOSE oldc; DEALLOCATE oldc;
    DECLARE @cert SYSNAME = N'pim_access_signer_' + FORMAT(SYSUTCDATETIME(), 'yyyyMMddHHmmss');
    DECLARE @pw NVARCHAR(200) = CONVERT(NVARCHAR(36), NEWID()) + N'Pa1!' + CONVERT(NVARCHAR(36), NEWID());
    SET @s = N'CREATE CERTIFICATE ' + QUOTENAME(@cert) + N' ENCRYPTION BY PASSWORD = ' + QUOTENAME(@pw, '''')
           + N' WITH SUBJECT = ''PIM Manager access procedure signer'', EXPIRY_DATE = ''20991231'';';
    EXEC sys.sp_executesql @s;
    SET @s = N'CREATE USER ' + QUOTENAME(@cert) + N' FROM CERTIFICATE ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    SET @s = N'GRANT CREATE ROLE, ALTER ANY ROLE, ALTER ANY USER, VIEW DEFINITION TO ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    -- CONTROL on the product schemas follows in the top-up below (it runs for the current signer on every admin run, so a
    -- new signer gets it right after it is signed).
    SET @s = N'ADD SIGNATURE TO [pim].[usp_ApplyAccess] BY CERTIFICATE ' + QUOTENAME(@cert) + N' WITH PASSWORD = ' + QUOTENAME(@pw, '''') + N';';
    EXEC sys.sp_executesql @s;
    SET @s = N'ALTER CERTIFICATE ' + QUOTENAME(@cert) + N' REMOVE PRIVATE KEY;'; EXEC sys.sp_executesql @s;
END
-- 2.4.644 TOP-UP (PIM 100.156, live 2026-10-16: pimdemo was created AFTER run 1 signed the procedure, and 4 of 47 statements
-- were refused -- the signer held CONTROL only on the schemas that existed at signing). For the CURRENT signer, on EVERY
-- admin run (idempotent; an install signed by an older release is repaired by its next admin run, no re-sign): CONTROL on
-- each product schema. (Real SQL, test VM 2026-10-16: the five permissions at DATABASE scope, with the grant option, do NOT
-- let the signer grant on a schema -- "Cannot find the schema" -- so a schema-level right is the only one that works, and
-- batch 1 makes sure all three schemas exist before the signing.)
DECLARE @tsg SYSNAME, @ts NVARCHAR(MAX);
SELECT TOP 1 @tsg = c.name FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
 WHERE cp.major_id = OBJECT_ID(N'pim.usp_ApplyAccess') AND c.name LIKE N'pim_access_signer%';
IF @tsg IS NOT NULL AND DATABASE_PRINCIPAL_ID(@tsg) IS NOT NULL
BEGIN
    SELECT @ts = STRING_AGG(CONVERT(NVARCHAR(MAX), N'GRANT CONTROL ON SCHEMA::' + QUOTENAME(name) + N' TO ' + QUOTENAME(@tsg) + N';'), N' ')
      FROM sys.schemas WHERE name IN (N'pim', N'platform', N'pimdemo');
    IF @ts IS NOT NULL EXEC sys.sp_executesql @ts;
END
"@)
    # v2: EVERY catalog role is created HERE, owned by dbo (the procedure cannot create a dbo-owned role). A role the
    # procedure created later is owned by its CALLER (a signature adds rights, not identity -- real SQL, VM 2026-10-15),
    # so every pim_* role not owned by dbo is handed to dbo here too.
    $roleLines = @(foreach ($r in (Get-PimSqlAccessCatalog).Keys) { "IF DATABASE_PRINCIPAL_ID(N'$r') IS NULL EXEC(N'CREATE ROLE [$r] AUTHORIZATION [dbo];');" })
    $ownLine = "DECLARE @own NVARCHAR(MAX); SELECT @own = STRING_AGG(CONVERT(NVARCHAR(MAX), N'ALTER AUTHORIZATION ON ROLE::' + QUOTENAME(name) + N' TO [dbo];'), N' ') FROM sys.database_principals WHERE type = 'R' AND is_fixed_role = 0 AND name LIKE N'pim[_]%' AND owning_principal_id <> 1; IF @own IS NOT NULL EXEC sys.sp_executesql @own;"
    [void]$b.Add((($roleLines -join "`n") + "`n" + $ownLine + "`n" + 'GRANT EXECUTE ON OBJECT::[pim].[usp_ApplyAccess] TO [pim_updater];'))
    if ("$UpdaterUserName" -and "$UpdaterAppId") {
        if ("$UpdaterUserName" -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw "Get-PimSqlAccessAdminBatches: '$UpdaterUserName' is not a safe database user name." }
        $g = [guid]"$UpdaterAppId"
        $n = "$UpdaterUserName".Replace("'", "''"); $q = "[$("$UpdaterUserName".Replace(']', ']]'))]"
        [void]$b.Add(@"
EXEC [pim].[usp_ApplyAccess] @Action = N'user', @Role = N'pim_updater', @UserName = N'$n', @AppId = '$g';
IF IS_ROLEMEMBER('db_ddladmin', N'$n') = 0 ALTER ROLE [db_ddladmin] ADD MEMBER $q;
"@)
    }
    return @($b.ToArray())
}

function Get-PimSqlAccessApplyBatches {
    <#
      EVERY update, run by the UPDATER's own contained user (pim_updater: EXECUTE on the procedure + db_ddladmin). No
      admin, no group, no Support app (P9). Converges: every catalog role exists, every catalog grant is applied, every
      -Users entry ({ userName; appId; role }) exists in its role. -Revoke takes extra grants back ({ role; perm; on }),
      computed by the caller from a read of sys.database_permissions against the catalog.
    #>
    [CmdletBinding()]
    param([System.Collections.IDictionary]$Catalog, [object[]]$Users = @(), [object[]]$Revoke = @())
    if (-not $Catalog) { $Catalog = Get-PimSqlAccessCatalog }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($role in $Catalog.Keys) {
        if (-not (Test-PimSqlAccessRoleName -Role $role)) { throw "Get-PimSqlAccessApplyBatches: '$role' is not pim_<letters>." }
        [void]$lines.Add("EXEC [pim].[usp_ApplyAccess] @Action = N'role', @Role = N'$role';")
    }
    foreach ($role in $Catalog.Keys) {
        foreach ($gr in @($Catalog[$role])) {
            $t = Test-PimSqlAccessGrant -Role $role -Perm $gr.perm -On $gr.on
            if (-not $t.ok) { throw "Get-PimSqlAccessApplyBatches: $role $($gr.perm) $($gr.on): $($t.problems -join '; ')" }
            [void]$lines.Add("EXEC [pim].[usp_ApplyAccess] @Action = N'grant', @Role = N'$role', @Permission = N'$($gr.perm)', @Target = N'$($gr.on)';")
        }
    }
    foreach ($r in @($Revoke | Where-Object { $_ })) {
        $t = Test-PimSqlAccessGrant -Role $r.role -Perm $r.perm -On $r.on
        if (-not $t.ok) { throw "Get-PimSqlAccessApplyBatches: revoke $($r.role) $($r.perm) $($r.on): $($t.problems -join '; ')" }
        [void]$lines.Add("EXEC [pim].[usp_ApplyAccess] @Action = N'revoke', @Role = N'$($r.role)', @Permission = N'$($r.perm)', @Target = N'$($r.on)';")
    }
    foreach ($u in @($Users | Where-Object { $_ })) {
        if (-not (Test-PimSqlAccessRoleName -Role $u.role)) { throw "Get-PimSqlAccessApplyBatches: user $($u.userName): role '$($u.role)' is not pim_<letters>." }
        if ("$($u.userName)" -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw "Get-PimSqlAccessApplyBatches: '$($u.userName)' is not a safe database user name." }
        $g = [guid]"$($u.appId)"
        [void]$lines.Add("EXEC [pim].[usp_ApplyAccess] @Action = N'user', @Role = N'$($u.role)', @UserName = N'$("$($u.userName)".Replace("'", "''"))', @AppId = '$g';")
    }
    return @($lines.ToArray())
}

function Get-PimSqlAccessStateSql {
    <#
      READ-ONLY. What the database holds today: the procedure (exists, this version, signed), the signer certificate's
      expiry + whether its private key is gone, and every grant held by a pim_* role -- so the updater can compute
      -Revoke and a cut-over can prove its result. Result sets: 1 = one row of facts, 2 = role / perm / on rows.
    #>
    [CmdletBinding()] param()
    $m = $script:PimSqlAccessMarker
    return @"
SELECT
  CASE WHEN OBJECT_ID(N'pim.usp_ApplyAccess') IS NULL THEN 0 ELSE 1 END AS procExists,
  CASE WHEN ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'pim.usp_ApplyAccess')), N'') LIKE N'%$m%' THEN 1 ELSE 0 END AS procCurrent,
  (SELECT TOP 1 c.name FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
     WHERE cp.major_id = OBJECT_ID(N'pim.usp_ApplyAccess')) AS signer,
  (SELECT TOP 1 c.expiry_date FROM sys.crypt_properties cp JOIN sys.certificates c ON c.thumbprint = cp.thumbprint
     WHERE cp.major_id = OBJECT_ID(N'pim.usp_ApplyAccess')) AS signerExpiry,
  (SELECT TOP 1 CASE WHEN c.pvt_key_encryption_type = 'NA' THEN 1 ELSE 0 END FROM sys.crypt_properties cp
     JOIN sys.certificates c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(N'pim.usp_ApplyAccess')) AS privateKeyRemoved;
SELECT r.name AS role, dp.permission_name AS perm,
  CASE dp.class WHEN 3 THEN N'SCHEMA::' + SCHEMA_NAME(dp.major_id)
                WHEN 1 THEN OBJECT_SCHEMA_NAME(dp.major_id) + N'.' + OBJECT_NAME(dp.major_id) END AS [on]
FROM sys.database_permissions dp JOIN sys.database_principals r ON r.principal_id = dp.grantee_principal_id
WHERE r.type = 'R' AND r.is_fixed_role = 0 AND r.name LIKE N'pim[_]%' AND dp.state IN ('G', 'W') AND dp.class IN (1, 3);
"@
}

function Get-PimSqlAccessRevokeList {
    <#
      PURE. Grants a pim_* role holds that the catalog does not list -> what the updater revokes, so access CONVERGES
      (a catalog that shrinks takes rights back). Never touches EXECUTE on the procedure (that is the admin grant to
      pim_updater, outside the catalog by design) and never a role the catalog does not name.
    #>
    [CmdletBinding()] param([object[]]$Held = @(), [System.Collections.IDictionary]$Catalog)
    if (-not $Catalog) { $Catalog = Get-PimSqlAccessCatalog }
    $want = @{}
    foreach ($role in $Catalog.Keys) { foreach ($gr in @($Catalog[$role])) { $want["$role|$($gr.perm)|$($gr.on)".ToLowerInvariant()] = $true } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($h in @($Held | Where-Object { $_ })) {
        if (-not $Catalog.Contains("$($h.role)")) { continue }
        if ("$($h.on)" -eq 'pim.usp_ApplyAccess') { continue }
        if (-not $want.ContainsKey("$($h.role)|$($h.perm)|$($h.on)".ToLowerInvariant())) {
            [void]$out.Add([pscustomobject]@{ role = "$($h.role)"; perm = "$($h.perm)"; on = "$($h.on)" })
        }
    }
    return @($out.ToArray())
}

function ConvertFrom-PimSqlSidToAppId {
    <# PURE. A contained Entra user's SID ('0x' + 16 bytes, Guid.ToByteArray order) back to its app (client) id. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Sid)
    $h = "$Sid".Trim() -replace '^0x', ''
    if ($h -notmatch '^[0-9A-Fa-f]{32}$') { return $null }
    $bytes = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $bytes[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
    return ([guid]::new($bytes)).ToString()
}

function Get-PimSqlAccessComponentUsers {
    <#
      PURE. Which EXISTING contained Entra users belong in which component role. -Principals: rows { name; sid } of
      sys.database_principals type E. -NameMap: role -> database user name(s) of this install (from the install names,
      CR5). Only users that already exist are returned (their SID gives the app id); a missing one is the setup's or a
      new component's job, never guessed here.
    #>
    [CmdletBinding()] param([object[]]$Principals = @(), [System.Collections.IDictionary]$NameMap)
    $byName = @{}; foreach ($p in @($Principals | Where-Object { $_ })) { $byName["$($p.name)".ToLowerInvariant()] = $p }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($role in $NameMap.Keys) {
        if (-not (Test-PimSqlAccessRoleName -Role $role)) { throw "Get-PimSqlAccessComponentUsers: '$role' is not pim_<letters>." }
        foreach ($n in @($NameMap[$role] | Where-Object { "$_" })) {
            $p = $byName["$n".ToLowerInvariant()]
            if (-not $p) { continue }
            $app = ConvertFrom-PimSqlSidToAppId -Sid "$($p.sid)"
            if (-not $app) { continue }
            [void]$out.Add([pscustomobject]@{ userName = "$($p.name)"; appId = $app; role = $role })
        }
    }
    return @($out.ToArray())
}

function Get-PimSqlAccessInstallNameMap {
    <# The install's database user names per component role (CR5 install names; today's names by default). #>
    # -NoRecord (setup, PIM 100.156 B): the names from the environment / today's defaults only -- no read of the store.
    [CmdletBinding()] param([switch]$NoRecord)
    $nr = [bool]$NoRecord
    $nm = { param($r, $d) if (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { try { if ($nr) { return (Get-PimInstallName -Role $r -NoRecord) } else { return (Get-PimInstallName -Role $r) } } catch { } }; return $d }
    return [ordered]@{
        pim_web      = @(& $nm 'web' 'ca-pim-manager')
        pim_engine   = @(& $nm 'engine' 'ca-pim-tick')
        pim_updater  = @(& $nm 'updater' 'ca-pim-update')
        pim_asbuilt  = @(& $nm 'asbuilt' 'caj-pim-asbuilt')
        pim_publish  = @(& $nm 'publish' 'ca-pim-publish')
        pim_downlink = @(& $nm 'downlink' 'ca-pim-downlink-s6')
    }
}

function Get-PimSqlComponentAccess {
    <#
      PURE (CR5 names via Get-PimInstallName when loaded). The ONE answer to "which database roles does this component's
      contained user get" for a NEW install (framework 12.23 P2/P3/P8, PIM 100.156 B). Setup, the in-network init job and
      the hybrid-worker grant all ask here, so the model cannot differ between them.
        web       pim_web                       engine    pim_engine (also every other ca-pim-* worker app)
        updater   pim_updater + db_ddladmin     asbuilt   pim_asbuilt
        publish   pim_publish                   downlink  pim_downlink + pim_engine (ca-pim-downlink*; it runs the
                                                          managed tenant's engine apply as a child)
        hybrid    pim_hybrid                    vmhost    pim_web + pim_engine + pim_updater + db_ddladmin (the VM
                                                          runs the Manager AND the engine AND applies its own schema)
      NEVER db_datareader / db_datawriter / db_owner. db_ddladmin only for the one identity that applies the schema.
      -Component wins; else the user name is matched against the install's names (Get-PimSqlAccessInstallNameMap).
      Returns { component; roles[] }.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$DbUserName = '',
          [ValidateSet('', 'web', 'engine', 'updater', 'asbuilt', 'publish', 'downlink', 'hybrid', 'vmhost')][string]$Component = '',
          [System.Collections.IDictionary]$NameMap)
    $c = "$Component"
    if (-not $c) {
        if (-not $NameMap) { $NameMap = Get-PimSqlAccessInstallNameMap -NoRecord }
        $n = "$DbUserName".Trim()
        foreach ($role in $NameMap.Keys) {
            if (@($NameMap[$role] | Where-Object { "$_" -and "$_" -ieq $n }).Count) { $c = "$role" -replace '^pim_', ''; break }
        }
        if (-not $c -and $n -match '^(?i)ca-pim-downlink') { $c = 'downlink' }
        if (-not $c) { $c = 'engine' }
    }
    $roles = switch ($c) {
        'web'      { @('pim_web') }
        'updater'  { @('pim_updater', 'db_ddladmin') }
        'asbuilt'  { @('pim_asbuilt') }
        'publish'  { @('pim_publish') }
        # the downlink job also runs the ENGINE APPLY of the managed tenant (Invoke-PimScenarioRun, a child of
        # downlink-job-entry.ps1), so it needs the engine's role beside its own (pim_downlink covers only the entry script).
        'downlink' { @('pim_downlink', 'pim_engine') }
        'hybrid'   { @('pim_hybrid') }
        'vmhost'   { @('pim_web', 'pim_engine', 'pim_updater', 'db_ddladmin') }
        default    { @('pim_engine') }
    }
    return [pscustomobject]@{ component = $c; roles = @($roles) }
}

function Get-PimSqlAccessPrerequisiteSql {
    <#
      PURE. What must exist BEFORE the admin batches sign the procedure, so the signer gets CONTROL on it: the platform
      schema (empty is fine -- the shipped schema fills it) and the demo tables (the web app has no DDL right in the
      model, so a first demo Enable must find them; PIM 100.156 run-2 note (a)). Idempotent. Admin only.
    #>
    [CmdletBinding()] param()
    $l = New-Object System.Collections.Generic.List[string]
    [void]$l.Add("IF SCHEMA_ID(N'platform') IS NULL EXEC(N'CREATE SCHEMA [platform] AUTHORIZATION [dbo];');")
    if (-not (Get-Command Get-PimDemoSchemaDdl -ErrorAction SilentlyContinue)) {
        $demo = Join-Path $PSScriptRoot 'PIM-DemoData.ps1'
        if (Test-Path -LiteralPath $demo) { . $demo }
    }
    if (Get-Command Get-PimDemoSchemaDdl -ErrorAction SilentlyContinue) {
        foreach ($s in ((Get-PimDemoSchemaDdl) -split "`r?`n" | Where-Object { "$_".Trim() })) { [void]$l.Add("$s") }
    } else {
        [void]$l.Add("IF SCHEMA_ID(N'pimdemo') IS NULL EXEC(N'CREATE SCHEMA [pimdemo] AUTHORIZATION [dbo];');")
    }
    return @($l.ToArray())
}

function Get-PimSqlAccessSetupGateSql {
    <#
      READ-ONLY. One row: is the procedure there (hasProc), and how many of the RUNTIME users (-UserNames: the web app and the
      engine of this install) hold a broad fixed role (broadUsers) -- the mark of an existing install never cut over. A
      support / extra user with broad roles does not count (a new install may declare one).
    #>
    [CmdletBinding()] param([string[]]$UserNames = @())
    $names = @($UserNames | Where-Object { "$_" -match '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$' } | ForEach-Object { "N'" + "$_".Replace("'", "''") + "'" })
    if (-not $names.Count) { $names = @("N''") }
    return @"
SELECT CASE WHEN OBJECT_ID(N'pim.usp_ApplyAccess') IS NULL THEN 0 ELSE 1 END AS hasProc,
  (SELECT COUNT(*) FROM sys.database_role_members m
     JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
     JOIN sys.database_principals u ON u.principal_id = m.member_principal_id
    WHERE r.name IN (N'db_datareader', N'db_datawriter') AND u.name IN ($($names -join ', '))) AS broadUsers;
"@
}

function Test-PimSqlAccessSetupGate {
    <#
      PURE (PIM 100.156 B, framework 12.23 P8). May SETUP run the admin half of the model on this database?
        * the procedure is there already (a new install re-run, or an install the cut-over moved)  -> yes (idempotent)
        * no contained user holds db_datareader / db_datawriter (a NEW install)                    -> yes
        * otherwise: an EXISTING install that was never cut over                                   -> NO: it moves by the
          scripted Support-app cut-over (the customer told beforehand, the owner's yes per batch), never as a side effect
          of re-running a setup script. Nothing is changed; the install keeps its current model.
      Returns { install; reason }.
    #>
    [CmdletBinding()] param([object]$Row)
    if ($null -eq $Row) { return [pscustomobject]@{ install = $false; reason = 'the database could not be read -- the least-privilege model was NOT installed' } }
    if ("$($Row.hasProc)" -eq '1') { return [pscustomobject]@{ install = $true; reason = 'the access procedure is installed -- converging (idempotent)' } }
    if ([int]"$($Row.broadUsers)" -eq 0) { return [pscustomobject]@{ install = $true; reason = 'a new store (no user holds a broad role) -- installing the least-privilege model' } }
    return [pscustomobject]@{ install = $false; reason = ("an EXISTING install that was never cut over ($($Row.broadUsers) user(s) still hold db_datareader / db_datawriter) -- " +
                                                         'the model is NOT installed by setup; it moves by the Support-app cut-over (framework 12.23 P8). Nothing changed.') }
}

function Invoke-PimSqlAccessConverge {
    <#
      Run by the UPDATER after the schema step (framework §12.23 P4/P9). Through the signed procedure ONLY:
        - not installed yet (no procedure / unsigned): changes NOTHING, returns applied = $false + the reason (the admin
          run -- setup or the Support-app cut-over -- installs it; the broad roles keep the install working meanwhile)
        - installed: every role + grant from the catalog, every existing component user into its role, extra grants
          revoked. Additive to the fixed roles: the broad roles are dropped only by the admin cut-over's SECOND run (P8).
      Never throws for a missing model; a failing EXEC throws (the caller reports it and does not block the update).
      -Query / -Exec: scriptblocks (cs, sql) for tests; default Invoke-PimSqlQuery / Invoke-PimSqlNonQuery.
    #>
    [CmdletBinding()]
    # -ConnectionString may be EMPTY when -Query / -Exec carry the caller's own open connection (the admin run, the
    # Support-app cut-over): a Mandatory [string] refused '' and the admin run threw before converging (VM gate4, 2026-10-15).
    param([AllowEmptyString()][string]$ConnectionString = '', [scriptblock]$Query, [scriptblock]$Exec, [System.Collections.IDictionary]$NameMap)
    if (-not "$ConnectionString" -and (-not $Query -or -not $Exec)) { throw 'Invoke-PimSqlAccessConverge: no connection string and no -Query/-Exec -- nothing to run against.' }
    if (-not $Query) { $Query = { param($cs, $sql) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql } }
    if (-not $Exec) { $Exec = { param($cs, $sql) [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql) } }
    if (-not $NameMap) { $NameMap = Get-PimSqlAccessInstallNameMap }
    # WHO this run is in the database (PIM 100.156: the proof that the updater converges as its OWN contained user, not as
    # dbo through the SQL admin group). Read-only, visible to every principal; never fails the converge.
    $runAs = ''; $dbOwner = $false
    try {
        $me = @(& $Query $ConnectionString "SELECT USER_NAME() AS userName, IS_ROLEMEMBER('db_owner') AS dbOwner;")[0]
        if ($me) { $runAs = "$($me.userName)"; $dbOwner = ("$($me.dbOwner)" -eq '1') }
    } catch { }
    $st = Get-PimSqlAccessState -ConnectionString $ConnectionString -Query $Query
    $facts = $st.facts
    if (-not $facts -or "$($facts.procExists)" -ne '1' -or -not "$($facts.signer)") {
        # A least-privilege caller sees no certificate in the catalog: an installed procedure WITHOUT the v2 state action
        # (marker v1) reads as unsigned here. Say so -- "not installed" would send support to the wrong fix.
        $why = if ($facts -and "$($facts.procExists)" -eq '1' -and "$($st.via)" -eq 'catalog' -and -not $dbOwner) {
            'the access procedure is installed but this identity cannot read its state (a procedure older than v2, or no EXECUTE on it) -- re-sign it with v2 (ops sqlaccess-cutover.ps1 through the Support app); nothing changed'
        } else { 'the access procedure is not installed yet -- an admin run (setup or the Support-app cut-over) installs it; nothing changed' }
        return [pscustomobject]@{ applied = $false; reason = $why; statements = 0; via = "$($st.via)"; runAs = $runAs; dbOwner = $dbOwner }
    }
    $held = @($st.held)
    # 🪤 Metadata visibility: a least-privilege updater (pim_updater + db_ddladmin, no ALTER ANY USER) sees ITSELF in
    # sys.database_principals, not the other components' users -- so after the updater leaves the SQL admin group this list
    # holds only the updater. Nothing is lost: the admin run (setup / the cut-over) converged every existing component user
    # into its role, and a user the UPDATER makes (the as-built reader) is passed with its app id. Reported as visibleUsers.
    $principals = @(& $Query $ConnectionString "SELECT name, CONVERT(VARCHAR(40), sid, 1) AS sid FROM sys.database_principals WHERE type = 'E';")
    $users = @(Get-PimSqlAccessComponentUsers -Principals $principals -NameMap $NameMap)
    $revoke = @(Get-PimSqlAccessRevokeList -Held $held)
    $all = @(Get-PimSqlAccessApplyBatches -Users $users -Revoke $revoke)
    # 2.4.644 (live 2026-10-16): a catalog grant the role ALREADY holds is converged -- it is not sent again, so it can never
    # be reported as refused (internal: 4 grants on SCHEMA::pimdemo were held -- an admin had applied them -- and still
    # logged as "4 of 47 refused"). The held list is what the state read returned (through the procedure: complete).
    $heldKey = @{}
    foreach ($h in $held) { if ($h -and "$($h.role)" -and "$($h.perm)" -and "$($h.on)") { $heldKey["grant|$($h.role)|$($h.perm)|$($h.on)".ToLowerInvariant()] = $true } }
    $lines = New-Object System.Collections.Generic.List[string]; $already = 0
    foreach ($l in $all) {
        if ($l -match "@Action = N'grant', @Role = N'([^']+)', @Permission = N'([^']+)', @Target = N'([^']+)';$" -and $heldKey.ContainsKey("grant|$($Matches[1])|$($Matches[2])|$($Matches[3])".ToLowerInvariant())) { $already++; continue }
        [void]$lines.Add($l)
    }
    # Every line is tried: one refusal (e.g. a schema the signer was never given a right on) must not leave the rest of the
    # catalog unapplied. Any refusal is then THROWN as one message (the caller reports it and never blocks the update).
    $failed = New-Object System.Collections.Generic.List[string]; $schemaRefused = $false
    foreach ($l in $lines) {
        try { & $Exec $ConnectionString $l }
        catch {
            if ($l -match "@Target = N'SCHEMA::") { $schemaRefused = $true }
            [void]$failed.Add(("{0} -> {1}" -f ($l -replace '^EXEC \[pim\]\.\[usp_ApplyAccess\] ', ''), (("$($_.Exception.Message)" -split "`n")[0])))
        }
    }
    if ($failed.Count) {
        # A schema-level refusal on an install signed before 2.4.644: the signer has no right on a product schema created after
        # the signing. Say what fixes it (the next admin run tops the signer up -- no re-sign) instead of a bare refusal.
        $hint = if ($schemaRefused) { ' -- a product schema created after the procedure was signed: the signer holds no right on it until the next admin run (setup re-run / the Support-app cut-over) tops it up; nothing else is affected' } else { '' }
        throw ("{0} of {1} access statement(s) refused through the signed procedure (as {2}): {3}{4}" -f $failed.Count, $lines.Count, $(if ($runAs) { $runAs } else { '?' }), (@($failed.ToArray() | Select-Object -First 3) -join ' | '), $hint)
    }
    return [pscustomobject]@{ applied = $true; reason = ''; statements = $lines.Count; alreadyHeld = $already; users = @($users | ForEach-Object { "$($_.userName)->$($_.role)" }); revoked = $revoke.Count
                              signer = "$($facts.signer)"; signerExpiry = $facts.signerExpiry; privateKeyRemoved = "$($facts.privateKeyRemoved)" -eq '1'
                              via = "$($st.via)"; runAs = $runAs; dbOwner = $dbOwner; visibleUsers = @($principals).Count }
}

function New-PimSqlAccessVerdict {
    <#
      PURE (§33.0 MORE TELEMETRY, field SqlAccess). The verdict the UPDATER records in UpdateState.sqlAccess after its access
      converge, so the heartbeat only READS it (the tick needs no right on the signed procedure):
        model                 least-privilege (the signed procedure is installed: run 1 happened) | broad (not installed)
        run1                  $true when the model is installed (the converge applied, or applied with some statements refused)
        run2                  $true when no RUNTIME user (web / engine) holds db_datareader / db_datawriter any more (the
                              cut-over's second run, framework 12.23 P8); $false when one does; $null when the updater cannot
                              see it (-BroadUsers $null: a least-privilege updater does not see the other users' roles)
        updaterInAdminGroup   the converge ran as dbo / db_owner (the updater is still in the SQL admin group)
        checkedUtc            when
      -Converge: what Invoke-PimSqlAccessConverge returned; -ErrorText: what it threw instead. Anything else = $null (no verdict).
    #>
    [CmdletBinding()] param([AllowNull()][object]$Converge = $null, [AllowEmptyString()][string]$ErrorText = '', [AllowNull()][object]$BroadUsers = $null,
                            [datetime]$NowUtc = [datetime]::UtcNow)
    $model = $null; $admin = $null
    if ($null -ne $Converge -and $Converge.PSObject.Properties['applied']) {
        $model = if ([bool]$Converge.applied) { 'least-privilege' } else { 'broad' }
        if ($Converge.PSObject.Properties['dbOwner']) { $admin = [bool]$Converge.dbOwner }
        if ($Converge.PSObject.Properties['runAs'] -and "$($Converge.runAs)" -eq 'dbo') { $admin = $true }
    } elseif ("$ErrorText" -match 'refused through the signed procedure') {
        # the procedure IS installed and ran; some statements were refused (e.g. a schema the signer has no CONTROL on)
        $model = 'least-privilege'
        if ("$ErrorText" -match '\(as ([^)]+)\)') { $who = $Matches[1].Trim(); if ($who -and $who -ne '?') { $admin = ($who -eq 'dbo') } }
    }
    if (-not $model) { return $null }
    $run2 = $null; $bn = 0
    if ($null -ne $BroadUsers -and [int]::TryParse("$BroadUsers", [ref]$bn)) { $run2 = ($bn -eq 0) }
    return [ordered]@{ model = $model; run1 = ($model -eq 'least-privilege'); run2 = $run2; updaterInAdminGroup = $admin; checkedUtc = $NowUtc.ToUniversalTime().ToString('o') }
}

function Test-PimSqlAccessInstalledState {
    <#
      PURE. Judge the read-back after an admin run: the procedure exists, is THIS version, is signed by a pim_access_signer
      certificate that expires in 2099 or later and holds no private key. Returns { ok; problems[] }. A missing row fails.
    #>
    [CmdletBinding()] param([object]$Facts)
    $p = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Facts) { return [pscustomobject]@{ ok = $false; problems = @('the read-back returned no row -- nothing is proven') } }
    if ("$($Facts.procExists)" -ne '1') { [void]$p.Add('the access procedure does not exist') }
    if ("$($Facts.procCurrent)" -ne '1') { [void]$p.Add('the access procedure is not this version') }
    if ("$($Facts.signer)" -notlike 'pim_access_signer*') { [void]$p.Add('the access procedure is not signed') }
    if (-not $Facts.signerExpiry -or ([datetime]$Facts.signerExpiry).Year -lt 2099) { [void]$p.Add("the signer certificate expires before 2099 ($($Facts.signerExpiry))") }
    if ("$($Facts.privateKeyRemoved)" -ne '1') { [void]$p.Add('the signer certificate still holds its private key') }
    return [pscustomobject]@{ ok = ($p.Count -eq 0); problems = @($p.ToArray()) }
}

function Invoke-PimSqlAccessInstall {
    <#
      The ADMIN run (framework §12.23 P4 / P8 run 1 / P9), shared by setup and the Support-app cut-over: the admin batches
      (procedure, certificate, signature, pim_updater + EXECUTE, the updater user), the read-back (Test-PimSqlAccessInstalledState),
      then ONE converge so every component user is in its role at once. ADDITIVE: no fixed-role membership is removed here
      (the broad roles go in the cut-over's SECOND run, after a green pipeline). Must run as an admin of the database.
      -Query / -Exec: scriptblocks (cs, sql) -- the caller's own connection (Support app, dbinit job, setup host).
      -WithPrerequisites (setup, PIM 100.156 B): first the platform schema + the demo tables (Get-PimSqlAccessPrerequisiteSql),
      so the signer gets CONTROL on every product schema and the web app never needs a DDL right. The cut-over omits it.
    #>
    [CmdletBinding()]
    param([string]$ConnectionString = '', [Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Exec,
          [string]$UpdaterUserName = '', [string]$UpdaterAppId = '', [System.Collections.IDictionary]$NameMap, [switch]$WithPrerequisites,
          # -SetupGate (setup, PIM 100.156 B): first Test-PimSqlAccessSetupGate -- an existing install never cut over is
          # LEFT ALONE (returns { ok; skipped = $true; reason }), the cut-over owns it (framework 12.23 P8).
          [switch]$SetupGate)
    if ($SetupGate) {
        $gm = if ($NameMap) { $NameMap } else { Get-PimSqlAccessInstallNameMap -NoRecord }
        $g = Test-PimSqlAccessSetupGate -Row (@(& $Query $ConnectionString (Get-PimSqlAccessSetupGateSql -UserNames (@($gm['pim_web']) + @($gm['pim_engine']))))[0])
        if (-not $g.install) { return [pscustomobject]@{ ok = $true; skipped = $true; reason = $g.reason; signer = ''; signerExpiry = $null; converge = $null } }
    }
    if ($WithPrerequisites) { foreach ($p in @(Get-PimSqlAccessPrerequisiteSql)) { & $Exec $ConnectionString $p } }
    foreach ($b in @(Get-PimSqlAccessAdminBatches -UpdaterUserName $UpdaterUserName -UpdaterAppId $UpdaterAppId)) { & $Exec $ConnectionString $b }
    $facts = (Get-PimSqlAccessState -ConnectionString $ConnectionString -Query $Query).facts
    $v = Test-PimSqlAccessInstalledState -Facts $facts
    if (-not $v.ok) { throw "the access model did not install: $($v.problems -join '; ')" }
    $conv = Invoke-PimSqlAccessConverge -ConnectionString $ConnectionString -Query $Query -Exec $Exec -NameMap $NameMap
    return [pscustomobject]@{ ok = $true; skipped = $false; reason = ''; signer = "$($facts.signer)"; signerExpiry = $facts.signerExpiry; converge = $conv }
}

function Get-PimSqlAccessState {
    <#
      The access state, read the way a LEAST-PRIVILEGE caller can see it (v2, SI's real-SQL finding 1: a ddladmin-only
      updater sees no grants and no certificates in the catalog views). First through the signed procedure
      (@Action = 'state'); when that is not possible (no procedure, the v1 procedure, no EXECUTE) the direct catalog read
      -- which an admin, or an updater still in the admin group, can see. Returns { facts; held; via }.
    #>
    [CmdletBinding()] param([AllowEmptyString()][string]$ConnectionString = '', [Parameter(Mandatory)][scriptblock]$Query)
    try {
        $f = @(& $Query $ConnectionString "EXEC [pim].[usp_ApplyAccess] @Action = N'state', @What = N'facts';")[0]
        if ($f -and "$($f.procExists)" -eq '1') {
            $h = @(& $Query $ConnectionString "EXEC [pim].[usp_ApplyAccess] @Action = N'state', @What = N'grants';")
            return [pscustomobject]@{ facts = $f; held = $h; via = 'procedure' }
        }
    } catch { }
    $parts = (Get-PimSqlAccessStateSql) -split ';\s*\r?\nSELECT r\.name', 2
    $f = @(& $Query $ConnectionString ($parts[0] + ';'))[0]
    $h = @(& $Query $ConnectionString ('SELECT r.name' + $parts[1]))
    return [pscustomobject]@{ facts = $f; held = $h; via = 'catalog' }
}

# ---- framework §12.23 P8 EXCEPTION (owner 2026-10-18): PRIVATE SQL, NEVER CUT OVER -- THE UPDATER STARTS THE IN-NETWORK
# ADMIN RUN. The Support app has no route to a private database, so the install's own in-network admin job (ca-pim-dbinit)
# does run 1 (Invoke-PimSqlAccessInstall) and, on a LATER update, run 2 (Invoke-PimSqlAccessRun2). The updater only
# decides (Get-PimSqlAccessCutoverStep) and starts the job; it never runs admin SQL itself (Test-PimSqlAccess L4).

$script:PimSqlAccessBroadRoles = @('db_datareader', 'db_datawriter', 'db_ddladmin')
$script:PimSqlAccessRun2MinHours = 12

function Get-PimSqlAccessSignerUtc {
    <# PURE. The UTC time run 1 signed the procedure, from the signer's name (pim_access_signer_yyyyMMddHHmmss); $null when unreadable. #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Signer)
    if ("$Signer" -notmatch '^pim_access_signer_(\d{14})$') { return $null }
    $d = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($Matches[1], 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture,
            ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$d)) { return $null }
    return $d
}

function Test-PimSqlAccessRunsGreenSince {
    <#
      PURE. Did the install's jobs run green since -SinceUtc? -Runs: the scheduler's JobRunHistory rows ({ name; status;
      startedUtc | startUtc }). Per job name, its LATEST run that started after -SinceUtc must not have failed, and at least
      -MinJobs different jobs must have run since. Returns { ok; reason; jobs }.
    #>
    [CmdletBinding()] param([object[]]$Runs = @(), [Parameter(Mandatory)][datetime]$SinceUtc, [int]$MinJobs = 3)
    $since = $SinceUtc.ToUniversalTime()
    $after = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Runs | Where-Object { $_ })) {
        $s = "$($r.startedUtc)"; if (-not $s.Trim()) { $s = "$($r.startUtc)" }
        $t = [datetime]::MinValue
        if (-not [datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$t)) { continue }
        if ($t -le $since) { continue }
        [void]$after.Add([pscustomobject]@{ name = "$($r.name)"; status = "$($r.status)"; t = $t })
    }
    $latest = @($after | Group-Object name | ForEach-Object { @($_.Group | Sort-Object t)[-1] })
    $bad = @($latest | Where-Object { "$($_.status)" -match '(?i)fail|error' })
    if ($bad.Count) { return [pscustomobject]@{ ok = $false; jobs = $latest.Count; reason = "$($bad.Count) job(s) failed on their latest run since run 1: $((@($bad | ForEach-Object name) | Select-Object -First 5) -join ', ')" } }
    if ($latest.Count -lt $MinJobs) { return [pscustomobject]@{ ok = $false; jobs = $latest.Count; reason = "only $($latest.Count) job(s) ran since run 1 (at least $MinJobs needed)" } }
    return [pscustomobject]@{ ok = $true; jobs = $latest.Count; reason = "$($latest.Count) job(s) ran since run 1, none failed on its latest run" }
}

function Get-PimSqlAccessCutoverStep {
    <#
      PURE. Framework §12.23 P8 EXCEPTION: which in-network admin run, if any, should the UPDATER start now?
        -PrivateSql        the store's SQL server has public network access OFF (a public one keeps the Support-app cut-over)
        -AdminJobOk        the install's in-network admin job exists and runs THIS release's image
        -UpdaterIsAdmin    the updater reached the store as dbo / db_owner (still in the SQL admin group: it can see the model)
        -HasProc           the signed access procedure exists (run 1 done)
        -BroadUsers        how many runtime users (web / engine) still hold db_datareader / db_datawriter
        -SignerUtc         when run 1 signed the procedure; -RunsGreen: Test-PimSqlAccessRunsGreenSince since then
      Returns { step = 'run1' | 'run2' | 'none'; reason }. run 2 never in the same update as run 1: at least
      $script:PimSqlAccessRun2MinHours after the signing, and only on green runs since.
    #>
    [CmdletBinding()]
    param([bool]$PrivateSql, [bool]$AdminJobOk, [bool]$UpdaterIsAdmin, [bool]$HasProc, [AllowNull()][object]$BroadUsers,
          [AllowNull()][object]$SignerUtc, [AllowNull()][object]$RunsGreen, [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($why) [pscustomobject]@{ step = 'none'; reason = $why } }
    if (-not $PrivateSql) { return (& $no 'public SQL: an existing install moves by the Support-app cut-over (framework 12.23 P8)') }
    if (-not $UpdaterIsAdmin) { return (& $no 'the updater is not in the SQL admin group -- nothing to decide (the install is past the cut-over, or it cannot see the model)') }
    $bn = 0
    $broadKnown = ($null -ne $BroadUsers -and [int]::TryParse("$BroadUsers", [ref]$bn))
    if (-not $HasProc) {
        if (-not $AdminJobOk) { return (& $no 'run 1 is due, but the in-network admin job is missing or not on this release yet') }
        return [pscustomobject]@{ step = 'run1'; reason = 'private SQL, never cut over: run 1 (the signed procedure, the roles, the updater''s own user -- additive) through the in-network admin job' }
    }
    if (-not $broadKnown) { return (& $no 'run 1 is done; whether run 2 is due could not be read') }
    if ($bn -eq 0) { return (& $no 'run 1 and run 2 are done (no runtime user holds a broad role)') }
    if (-not $AdminJobOk) { return (& $no 'run 2 is due, but the in-network admin job is missing or not on this release yet') }
    if ($null -eq $SignerUtc) { return (& $no 'run 2 waits: the time of run 1 could not be read from the signer') }
    $age = ($NowUtc.ToUniversalTime() - ([datetime]$SignerUtc).ToUniversalTime()).TotalHours
    if ($age -lt $script:PimSqlAccessRun2MinHours) { return (& $no ("run 2 waits: run 1 is {0:N1} h old (at least {1} h)" -f $age, $script:PimSqlAccessRun2MinHours)) }
    if ($null -eq $RunsGreen -or -not [bool]$RunsGreen.ok) { return (& $no ("run 2 waits: $(if ($RunsGreen) { $RunsGreen.reason } else { 'the run history could not be read' })")) }
    return [pscustomobject]@{ step = 'run2'; reason = ("private SQL, run 1 done {0:N0} h ago and green since ({1}): run 2 (the broad roles off the web app and the engine) through the in-network admin job" -f $age, $RunsGreen.reason) }
}

function Get-PimSqlAccessRun2Plan {
    <#
      READ-ONLY. Run 2 (framework 12.23 P8: the broad roles off the RUNTIME users) -- its gates and what it would drop.
      Gates: the signed procedure present + current + signed; web in pim_web and engine in pim_engine, neither db_owner; the
      updater (when it has a user) in pim_updater + db_ddladmin; every web + engine catalog grant held whose object exists
      (pimdemo always). -Query (cs, sql): the caller's connection. Returns { ok; gates[]; drop[] ({role; member}); users }.
    #>
    [CmdletBinding()] param([AllowEmptyString()][string]$ConnectionString = '', [Parameter(Mandatory)][scriptblock]$Query, [System.Collections.IDictionary]$NameMap)
    if (-not $NameMap) { $NameMap = Get-PimSqlAccessInstallNameMap }
    $gates = New-Object System.Collections.Generic.List[object]
    $gate = { param($name, $ok, $detail) [void]$gates.Add([pscustomobject]@{ name = $name; ok = [bool]$ok; detail = "$detail" }) }
    $parts = (Get-PimSqlAccessStateSql) -split ';\s*\r?\nSELECT r\.name', 2
    $facts = @(& $Query $ConnectionString ($parts[0] + ';'))[0]
    $held = @(& $Query $ConnectionString ('SELECT r.name' + $parts[1]))
    & $gate 'signed procedure present + current' ($facts -and "$($facts.procExists)" -eq '1' -and "$($facts.procCurrent)" -eq '1' -and "$($facts.signer)") "signer $($facts.signer)"
    $webUser = "$(@($NameMap['pim_web'])[0])"; $engUser = "$(@($NameMap['pim_engine'])[0])"; $updUser = "$(@($NameMap['pim_updater'])[0])"
    $mem = @(& $Query $ConnectionString "SELECT r.name AS role, u.name AS member FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals u ON u.principal_id = m.member_principal_id;")
    $in = { param($u, $r) [bool](@($mem | Where-Object { "$($_.member)" -ieq $u -and "$($_.role)" -ieq $r }).Count) }
    foreach ($p in @(@($webUser, 'pim_web'), @($engUser, 'pim_engine'))) {
        & $gate "$($p[0]) is in $($p[1])" (& $in $p[0] $p[1]) ''
        & $gate "$($p[0]) is NOT db_owner" (-not (& $in $p[0] 'db_owner')) 'db_owner is never taken away by run 2'
    }
    $updHas = [bool](@($mem | Where-Object { "$($_.member)" -ieq $updUser }).Count)
    if ($updHas) { & $gate "updater [$updUser] keeps db_ddladmin + is in pim_updater" ((& $in $updUser 'db_ddladmin') -and (& $in $updUser 'pim_updater')) '' }
    $cat = Get-PimSqlAccessCatalog
    $heldKey = @{}; foreach ($h in $held) { if ($h) { $heldKey["$($h.role)|$($h.perm)|$($h.on)".ToLowerInvariant()] = $true } }
    $gap = New-Object System.Collections.Generic.List[string]
    foreach ($role in 'pim_web', 'pim_engine') {
        foreach ($g in @($cat[$role])) {
            if ($heldKey.ContainsKey("$role|$($g.perm)|$($g.on)".ToLowerInvariant())) { continue }
            $on = "$($g.on)"
            $existsSql = if ($on -like 'SCHEMA::*') { "SELECT CASE WHEN SCHEMA_ID(N'{0}') IS NULL THEN 0 ELSE 1 END AS e;" -f ($on -replace '^SCHEMA::', '').Replace("'", "''") }
                         else { "SELECT CASE WHEN OBJECT_ID(N'{0}') IS NULL THEN 0 ELSE 1 END AS e;" -f $on.Replace("'", "''") }
            $exists = "$(@(& $Query $ConnectionString $existsSql)[0].e)" -eq '1'
            if ($exists -or $on -eq 'SCHEMA::pimdemo') { [void]$gap.Add("$role $($g.perm) $on") }
        }
    }
    & $gate 'every web + engine catalog grant held (pimdemo too)' (-not $gap.Count) ($gap -join '; ')
    $drop = @(foreach ($u in $webUser, $engUser) { foreach ($r in $script:PimSqlAccessBroadRoles) { if (& $in $u $r) { [pscustomobject]@{ role = $r; member = $u } } } })
    return [pscustomobject]@{ ok = (-not @($gates | Where-Object { -not $_.ok }).Count); gates = @($gates.ToArray()); drop = $drop; users = @($webUser, $engUser) }
}

function Get-PimSqlAccessRun2ProofSql {
    <# PURE. One row for -UserName, read AS that user: it reads + writes its store and can NOT create a table or hold a broad role. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$UserName)
    if ("$UserName" -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw "Get-PimSqlAccessRun2ProofSql: '$UserName' is not a safe database user name." }
    $n = "$UserName".Replace("'", "''")
    return ("EXECUTE AS USER = N'$n'; SELECT (SELECT COUNT(*) FROM pim.Settings) AS settingsRows, HAS_PERMS_BY_NAME(N'pim.Rows', N'OBJECT', N'INSERT') AS rowsInsert, " +
            "HAS_PERMS_BY_NAME(N'pim.Settings', N'OBJECT', N'UPDATE') AS settingsUpdate, HAS_PERMS_BY_NAME(NULL, N'DATABASE', N'CREATE TABLE') AS createTable, " +
            "IS_ROLEMEMBER(N'db_datareader') AS reader, IS_ROLEMEMBER(N'db_datawriter') AS writer, IS_ROLEMEMBER(N'db_ddladmin') AS ddl; REVERT;")
}

function Test-PimSqlAccessRun2Proof {
    <# PURE. Judge one proof row (Get-PimSqlAccessRun2ProofSql). Returns { ok; detail }. #>
    [CmdletBinding()] param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return [pscustomobject]@{ ok = $false; detail = 'no proof row' } }
    $rows = 0; [void][int]::TryParse("$($Row.settingsRows)", [ref]$rows)
    $ok = ($rows -gt 0) -and "$($Row.rowsInsert)" -eq '1' -and "$($Row.settingsUpdate)" -eq '1' -and "$($Row.createTable)" -eq '0' -and
          "$($Row.reader)" -eq '0' -and "$($Row.writer)" -eq '0' -and "$($Row.ddl)" -eq '0'
    return [pscustomobject]@{ ok = [bool]$ok; detail = ("reads pim.Settings ($rows rows), INSERT pim.Rows $($Row.rowsInsert), UPDATE pim.Settings $($Row.settingsUpdate), CREATE TABLE $($Row.createTable), db_datareader $($Row.reader), db_datawriter $($Row.writer), db_ddladmin $($Row.ddl)") }
}

function Invoke-PimSqlAccessRun2 {
    <#
      The ADMIN run 2 (framework 12.23 P8), from inside: Get-PimSqlAccessRun2Plan; REFUSES (throws, nothing changed) unless
      every gate is green; drops the broad roles from the web app + engine; proves each user AS that user
      (Test-PimSqlAccessRun2Proof). A failed proof PUTS BACK every membership it dropped and throws -- an unattended run has
      nobody to roll it back, so it never leaves an install worse than it found it. Must run as an admin of the database.
      Returns { dropped[]; proofs[]; nothingToDo }.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ConnectionString = '', [Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Exec, [System.Collections.IDictionary]$NameMap)
    $plan = Get-PimSqlAccessRun2Plan -ConnectionString $ConnectionString -Query $Query -NameMap $NameMap
    $red = @($plan.gates | Where-Object { -not $_.ok })
    if ($red.Count) { throw ("run 2 REFUSED, nothing changed -- gate(s) red: " + (($red | ForEach-Object { "$($_.name)$(if ($_.detail) { " ($($_.detail))" })" }) -join '; ')) }
    if (-not @($plan.drop).Count) { return [pscustomobject]@{ dropped = @(); proofs = @(); nothingToDo = $true } }
    $q = { param($s) "[$("$s".Replace(']', ']]'))]" }
    $done = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($d in @($plan.drop)) {
            & $Exec $ConnectionString ("ALTER ROLE {0} DROP MEMBER {1};" -f (& $q $d.role), (& $q $d.member))
            [void]$done.Add($d)
        }
        $proofs = New-Object System.Collections.Generic.List[object]
        foreach ($u in @($plan.users)) {
            $pr = Test-PimSqlAccessRun2Proof -Row (@(& $Query $ConnectionString (Get-PimSqlAccessRun2ProofSql -UserName $u))[0])
            [void]$proofs.Add([pscustomobject]@{ user = $u; ok = $pr.ok; detail = $pr.detail })
        }
        $bad = @($proofs | Where-Object { -not $_.ok })
        if ($bad.Count) { throw ("run 2 proof FAILED: " + (($bad | ForEach-Object { "$($_.user): $($_.detail)" }) -join ' | ')) }
        return [pscustomobject]@{ dropped = @($done.ToArray()); proofs = @($proofs.ToArray()); nothingToDo = $false }
    } catch {
        $err = "$($_.Exception.Message)"
        $back = New-Object System.Collections.Generic.List[string]
        foreach ($d in @($done.ToArray())) {
            try { & $Exec $ConnectionString ("ALTER ROLE {0} ADD MEMBER {1};" -f (& $q $d.role), (& $q $d.member)); [void]$back.Add("$($d.member)->$($d.role)") } catch { }
        }
        throw ("$err -- PUT BACK $($back.Count) of $($done.Count) dropped membership(s)$(if ($back.Count) { ': ' + ($back -join ', ') }); the install is on the broad roles as before")
    }
}
