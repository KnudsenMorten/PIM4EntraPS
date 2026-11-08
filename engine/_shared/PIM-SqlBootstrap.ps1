# =================================================================================================
# PIM-SqlBootstrap.ps1 -- the database's own setup, decided PURELY.
#
# 🔑 WHY THIS EXISTS. A policy-restricted tenant creates Azure SQL with publicNetworkAccess
# disabled -- correct: SQL needs no inbound path from the internet. But the deploy used to connect
# to SQL from the DEPLOY HOST to create the contained users, and with the public endpoint closed
# there is no route for that connection. Making the deploy identity the Entra admin only made it
# worse: it handed administration to the one identity that cannot reach the server.
#
# The environment administers its own database instead. A one-shot Container Apps job runs INSIDE
# the VNet, reaches SQL over its private endpoint, and authenticates as the user-assigned managed
# identity that IS the server's Entra admin. Nothing public, no deploy host, no credential.
#
# THIS FILE HOLDS ONLY THE DECISIONS -- which principals must exist, what SID each one has, and the
# exact DDL. No connection, no token, no az. That is what makes it testable offline, and the SID
# arithmetic is the part that must not be wrong: a SID built the wrong way round creates a user that
# EXISTS, looks correct in every listing, and can never authenticate.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary.
# =================================================================================================

Set-StrictMode -Off

function ConvertTo-PimSqlSid {
    <#
      The SID of a contained user is its APP ID -- not the object id -- as a little-endian GUID
      byte string. Getting this wrong is silent: the CREATE USER succeeds and the login never does.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$AppId)
    if (-not "$AppId".Trim()) { throw 'ConvertTo-PimSqlSid: empty appId -- refusing to build an empty SID.' }
    $g = [guid]"$AppId".Trim()
    return '0x' + (($g.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function New-PimSqlUserDdl {
    <#
      The idempotent create-or-repoint for one contained user.

      🔴 BUG-47 -- THIS IS NOT AN UNCONDITIONAL DROP + CREATE, AND MUST NOT BECOME ONE. The user
      holds db_ddladmin (it applies the schema), so once it creates a schema it OWNS that schema,
      and an owner cannot be dropped:
          "The database principal owns a schema in the database, and cannot be dropped."
      So: recreate ONLY when the SID actually differs -- which is exactly the case a rebuilt
      identity produces -- and hand any owned schema to dbo first so the drop can proceed. Role
      membership is applied guarded, because ALTER ROLE on an existing member is a no-op we should
      not rely on.

      Identical in shape to Grant-PimMiSql's host-side DDL on purpose: one behaviour, whichever
      side runs it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DbUserName,
        [Parameter(Mandatory)][string]$Sid,
        # PIM 100.156 B (framework 12.23 P3): NO default broad set any more -- the caller names the component's roles
        # (Get-PimSqlComponentAccess). A pim_<x> role that does not exist yet is created owned by dbo (this runs as admin).
        [string[]]$Roles = @()
    )
    if ("$DbUserName" -match "[\[\]']") { throw "New-PimSqlUserDdl: refusing a database user name containing brackets or quotes: '$DbUserName'" }
    if ("$Sid" -notmatch '^0x[0-9A-Fa-f]{32}$') { throw "New-PimSqlUserDdl: '$Sid' is not a 16-byte SID literal." }
    $lit = $DbUserName -replace "'", "''"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$lit' AND sid = $Sid)")
    [void]$sb.AppendLine('BEGIN')
    [void]$sb.AppendLine("    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$lit')")
    [void]$sb.AppendLine('    BEGIN')
    [void]$sb.AppendLine('        DECLARE @reassign NVARCHAR(MAX);')
    [void]$sb.AppendLine("        SELECT @reassign = STRING_AGG('ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME(s.name) + ' TO [dbo];', ' ')")
    [void]$sb.AppendLine('        FROM sys.schemas s JOIN sys.database_principals p ON s.principal_id = p.principal_id')
    [void]$sb.AppendLine("        WHERE p.name = '$lit';")
    [void]$sb.AppendLine('        IF @reassign IS NOT NULL EXEC sp_executesql @reassign;')
    [void]$sb.AppendLine("        DROP USER [$DbUserName];")
    [void]$sb.AppendLine('    END')
    [void]$sb.AppendLine("    CREATE USER [$DbUserName] WITH SID = $Sid, TYPE = E;")
    [void]$sb.AppendLine('END')
    foreach ($r in @($Roles | Where-Object { "$_".Trim() })) {
        if ("$r" -match "[\[\]']") { throw "New-PimSqlUserDdl: refusing a role name containing brackets or quotes: '$r'" }
        # an explicitly named fixed role (an operator / support principal) is kept as named -- a COMPONENT never gets one
        # by default any more (Get-PimSqlComponentAccess).
        if ("$r" -cmatch '^pim_[a-z]{2,30}$') { [void]$sb.AppendLine("IF DATABASE_PRINCIPAL_ID(N'$r') IS NULL EXEC(N'CREATE ROLE [$r] AUTHORIZATION [dbo];');") }
        [void]$sb.AppendLine("IF IS_ROLEMEMBER('$r','$lit') = 0 ALTER ROLE [$r] ADD MEMBER [$DbUserName];")
    }
    return $sb.ToString()
}

function Get-PimSqlBootstrapPlan {
    <#
      PURE. Turns the principals an environment needs into an ordered list of {name, appId, sid,
      roles, ddl}, and reports what it REFUSED and why rather than dropping it.

      Principals: @( @{ name='ca-pim-manager'; appId='<guid>'; roles=@(...) }, ... )

      🔒 A PRINCIPAL WITH NO APP ID IS A PROBLEM, NEVER A SKIP. That is the case where a managed
      identity has not replicated to Graph yet, and silently omitting it produces a database that
      looks set up and an app that cannot log in.
    #>
    [CmdletBinding()] param([object[]]$Principals = @())
    $plan = @{ users = @(); problems = @() }
    foreach ($p in @($Principals)) {
        $name = "$($p.name)".Trim()
        $app  = "$($p.appId)".Trim()
        if (-not $name) { $plan.problems += 'a principal has no name'; continue }
        if (-not $app)  { $plan.problems += "no appId for '$name' -- refusing to build a SID from nothing"; continue }
        $sid = $null
        try { $sid = ConvertTo-PimSqlSid -AppId $app } catch { $plan.problems += "bad appId for '$name': $($_.Exception.Message)"; continue }
        $roles = @($p.roles | Where-Object { "$_".Trim() })
        # PIM 100.156 B: a principal without roles gets its COMPONENT's roles (Get-PimSqlComponentAccess, PIM-SqlAccess.ps1)
        # -- never the old db_datareader + db_datawriter + db_ddladmin. Catalog not loaded: a problem, never a guess.
        if (-not $roles.Count) {
            if (Get-Command Get-PimSqlComponentAccess -ErrorAction SilentlyContinue) { $roles = @((Get-PimSqlComponentAccess -DbUserName $name).roles) }
            else { $plan.problems += "no roles for '$name' and the access catalog (PIM-SqlAccess.ps1) is not loaded -- refusing to guess"; continue }
        }
        $ddl = $null
        try { $ddl = New-PimSqlUserDdl -DbUserName $name -Sid $sid -Roles $roles } catch { $plan.problems += "$name : $($_.Exception.Message)"; continue }
        $plan.users += @{ name = $name; appId = $app; sid = $sid; roles = $roles; ddl = $ddl
                          # PIM item 21 (2026-11-08): this user OWNS schema 'signin' + may CREATE TABLE (the sign-in front's state)
                          signinOwner = [bool]$(if ($p -is [System.Collections.IDictionary]) { $p['signinOwner'] } elseif ($p.PSObject.Properties['signinOwner']) { $p.signinOwner } else { $false }) }
    }
    return $plan
}

# ---- PIM item 21 (incident 2026-11-08 08:46Z): THE SIGN-IN FRONT'S SQL STATE, as a database-job step ('signin-owner') ------
# The sign-in front signs in to SQL as the WEB identity and keeps its key ring in schema 'signin', which that identity must OWN
# (+ CREATE TABLE). The install makes it so once (tools/setup/_PimInstallSigninFront.ps1 Get-PimInstallSigninFrontSqlPlan); an
# identity move to id-pim-web gave the new user only pim_web -> SQL 262, no key ring, every page 500. So the database job
# converges it on every run for the principal its list marks signinOwner = true. The same three statements as the install,
# duplicated here (the engine library does not load setup code); the guard below allows exactly these and nothing else.
function Get-PimSigninOwnerSqlPlan {
    <# PURE. The statements that make -User own schema signin and hold CREATE TABLE, from what was read: -Owner (the schema's
       owner now, '' = no schema), -CreateTableGranted. The user itself is made by the users step. Never a role, never data. #>
    param([Parameter(Mandatory)][string]$User, [AllowEmptyString()][string]$Owner = '', [bool]$CreateTableGranted = $false)
    if ($User -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw "not a database user name: $User" }
    $plan = New-Object System.Collections.Generic.List[string]
    if (-not "$Owner".Trim()) { $plan.Add("EXEC(N'CREATE SCHEMA signin AUTHORIZATION [$User]')") }
    elseif ("$Owner".Trim() -ne $User) { $plan.Add("ALTER AUTHORIZATION ON SCHEMA::signin TO [$User]") }
    if (-not $CreateTableGranted) { $plan.Add("GRANT CREATE TABLE TO [$User]") }
    return @($plan)
}

function Test-PimSigninOwnerSqlSafe {
    <# PURE. Every statement is one of the three shapes Get-PimSigninOwnerSqlPlan makes -- anything else refuses the step.
       @{ ok; violations } #>
    param([string[]]$Statements = @())
    $allowed = @(
        '^EXEC\(N''CREATE SCHEMA signin AUTHORIZATION \[[A-Za-z0-9_.-]{1,128}\]''\)$',
        '^ALTER AUTHORIZATION ON SCHEMA::signin TO \[[A-Za-z0-9_.-]{1,128}\]$',
        '^GRANT CREATE TABLE TO \[[A-Za-z0-9_.-]{1,128}\]$')
    $bad = @(foreach ($s in @($Statements)) { $t = "$s".Trim(); if (-not @($allowed | Where-Object { $t -cmatch $_ }).Count) { $t } })
    return [pscustomobject]@{ ok = (-not $bad.Count); violations = $bad }
}

function Get-PimSigninOwnerReadQuery {
    <# PURE. One row: owner (schema signin's owner, NULL = no schema), createTable (1 when -User holds CREATE TABLE). #>
    param([Parameter(Mandatory)][string]$User)
    if ($User -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw "not a database user name: $User" }
    return ("SELECT (SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin') AS owner, " +
            "(SELECT COUNT(*) FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID(N'$User') AND permission_name = N'CREATE TABLE' AND state IN ('G', 'W')) AS createTable")
}

# ---- PIM item 21 (b) / framework 12.11c ruling (b): the OLD database users of moved roles are DROPPED by the database job -------
# ('drop-old-users', a REMOVAL step). Asked by app id (PIM_DBINIT_DROP_USERS = '["<app id>", ...]'), found by SID. REFUSED, never
# dropped: a SID a principal of this job's own list uses, a standard id-pim-* user, the Invardia Support app's user, a built-in user,
# an Entra GROUP (type X: the SQL admin group), a user that is not an Entra
# (external) user, a user that OWNS a schema, a user holding an explicit permission. The only statement: DROP USER [name].
function Get-PimDropUsersPlan {
    <# PURE. -AppIds asked; -Existing rows { name; sid ('0x..'); type ('E'/'X'/...); ownsSchema (int); explicitPerms (int) };
       -KeepSids the SIDs of this job's own principals. Returns @{ drop = @(names); refused = @('name: why'); absent = @(app ids) }. #>
    param([string[]]$AppIds = @(), [object[]]$Existing = @(), [string[]]$KeepSids = @())
    $out = [ordered]@{ drop = New-Object System.Collections.Generic.List[string]; refused = New-Object System.Collections.Generic.List[string]; absent = New-Object System.Collections.Generic.List[string] }
    $keep = @($KeepSids | ForEach-Object { "$_".ToUpperInvariant() })
    foreach ($a in @($AppIds | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)) {
        $sid = $null; try { $sid = (ConvertTo-PimSqlSid -AppId $a).ToUpperInvariant() } catch { $out.refused.Add("${a}: not an app id"); continue }
        $row = @($Existing | Where-Object { "$($_.sid)".ToUpperInvariant() -eq $sid }) | Select-Object -First 1
        if (-not $row) { $out.absent.Add($a); continue }
        $n = "$($row.name)"
        if ($keep -contains $sid)                                      { $out.refused.Add("${n}: a principal of this job's own list uses it"); continue }
        if ($n -match '^(?i)id-pim-')                                  { $out.refused.Add("${n}: a standard id-pim-* user is never dropped here"); continue }
        if ($n -in @('dbo', 'guest', 'sys', 'INFORMATION_SCHEMA'))     { $out.refused.Add("${n}: a built-in user"); continue }
        if ($n -match '(?i)invardia-support')                         { $out.refused.Add("${n}: the Invardia Support app's user is never dropped here"); continue }
        if ("$($row.type)" -ne 'E')                                 { $out.refused.Add("${n}: not an Entra app / user (a group or a SQL user is never dropped here)"); continue }
        if ([int]$row.ownsSchema -gt 0)                                { $out.refused.Add("${n}: owns a schema -- move the schema first (signin-owner)"); continue }
        if ([int]$row.explicitPerms -gt 0)                             { $out.refused.Add("${n}: holds an explicit permission -- not dropped blindly"); continue }
        if ($n -notmatch '^[A-Za-z0-9_.-]{1,128}$')                    { $out.refused.Add("${n}: not a plain user name"); continue }
        $out.drop.Add($n)
    }
    return [pscustomobject]@{ drop = @($out.drop); refused = @($out.refused); absent = @($out.absent) }
}

function Get-PimDropUsersReadQuery {
    <# PURE. Every database user with its SID, type, whether it owns a schema and how many explicit permissions it holds (CONNECT
       excluded -- every user holds it). #>
    return ("SELECT dp.name, CONVERT(VARCHAR(100), dp.sid, 1) AS sid, dp.type, " +
            "(SELECT COUNT(*) FROM sys.schemas s WHERE s.principal_id = dp.principal_id) AS ownsSchema, " +
            "(SELECT COUNT(*) FROM sys.database_permissions p WHERE p.grantee_principal_id = dp.principal_id AND p.permission_name <> 'CONNECT') AS explicitPerms " +
            "FROM sys.database_principals dp WHERE dp.type IN ('E', 'X', 'S', 'U', 'G')")
}

function Test-PimDropUsersSqlSafe {
    <# PURE. Every statement is exactly DROP USER [plain name]. @{ ok; violations } #>
    param([string[]]$Statements = @())
    $bad = @(foreach ($s in @($Statements)) { $t = "$s".Trim(); if ($t -cnotmatch '^DROP USER \[[A-Za-z0-9_.-]{1,128}\]$') { $t } })
    return [pscustomobject]@{ ok = (-not $bad.Count); violations = $bad }
}

function Test-PimSqlBootstrapDdlSafe {
    <#
      🔴 THE BLAST-RADIUS GUARD. This bootstrap runs unattended, as a database ADMIN, against a
      customer's production store. Its legitimate footprint is tiny: principals and role
      membership. Nothing it does should ever touch a table, a row, or a schema's contents.

      "It only creates users" is a claim about today's code. This is the claim ENFORCED -- every
      statement about to be executed is checked, and anything data-destructive refuses the run
      rather than being executed and reported.

      ALLOWED, and nothing else:
        CREATE USER / DROP USER            -- the principal itself (drop only on a SID mismatch)
        ALTER ROLE ... ADD MEMBER          -- role membership
        ALTER AUTHORIZATION ON SCHEMA::    -- hand an owned schema to dbo so the drop can proceed.
                                              A permission change, NOT a content change.
        IF / BEGIN / END / SELECT / DECLARE / EXEC sp_executesql  -- the guards around them

      REFUSED: DROP TABLE, DROP SCHEMA, DROP DATABASE, TRUNCATE, DELETE, UPDATE, INSERT, MERGE,
      ALTER TABLE, sp_rename, and anything else that could change or remove DATA.

      Returns @{ ok; violations }.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Ddl)
    $bad = @(
        @{ rx = '(?i)\bDROP\s+TABLE\b';        why = 'DROP TABLE' }
        @{ rx = '(?i)\bDROP\s+SCHEMA\b';       why = 'DROP SCHEMA' }
        @{ rx = '(?i)\bDROP\s+DATABASE\b';     why = 'DROP DATABASE' }
        @{ rx = '(?i)\bDROP\s+COLUMN\b';       why = 'DROP COLUMN' }
        @{ rx = '(?i)\bTRUNCATE\b';            why = 'TRUNCATE' }
        @{ rx = '(?i)\bDELETE\s+FROM\b';       why = 'DELETE' }
        @{ rx = '(?i)\bUPDATE\s+\w';           why = 'UPDATE' }
        @{ rx = '(?i)\bINSERT\s+INTO\b';       why = 'INSERT' }
        @{ rx = '(?i)\bMERGE\b';               why = 'MERGE' }
        @{ rx = '(?i)\bALTER\s+TABLE\b';       why = 'ALTER TABLE' }
        # 🪤 CREATE TABLE too, even though it destroys nothing. This guard's contract is "principals
        # and role membership, NOTHING ELSE", and the way it stops being true is by someone widening
        # the user path to also do a little schema work -- at which point the narrow guard silently
        # becomes the broad one. Schema work has its own guard (Test-PimSqlSchemaFileSafe) and its
        # own precondition (an empty store); it does not belong on this path at all.
        @{ rx = '(?i)\bCREATE\s+TABLE\b';      why = 'CREATE TABLE' }
        @{ rx = '(?i)\bsp_rename\b';           why = 'sp_rename' }
        @{ rx = '(?i)\bBACKUP\b|\bRESTORE\b';  why = 'BACKUP/RESTORE' }
    )
    $v = @()
    foreach ($b in $bad) { if ("$Ddl" -match $b.rx) { $v += $b.why } }
    return @{ ok = (@($v).Count -eq 0); violations = @($v) }
}

function Test-PimSqlSchemaFileSafe {
    <#
      🔴 THE SAME QUESTION, ASKED OF THE SHIPPED SCHEMA FILES.

      With a PRIVATE SQL server the base schema cannot be applied from the deploy host either --
      there is no route -- so the in-cloud bootstrap applies sql/platform-schema.sql as well
      (the only shipped base-schema file since sql/local-schema.sql was retired 2026-09-18,
      IMP-46). That is a bigger footprint than creating users, and it runs
      unattended against a customer's store, so it gets its own guard rather than inheriting the
      user-DDL one (which refuses CREATE TABLE and would be wrong here).

      🔴 THE REAL ENFORCEMENT IS NOT THIS FUNCTION -- IT IS "ONLY EVER APPLY TO AN EMPTY STORE",
      checked as a RUNTIME FACT by the job (zero tables in the 'pim' schema) before these files are
      executed. That is stronger than any regex, and it is what makes the shipped files safe:
      sql/platform-schema.sql line 91 carries
          IF COL_LENGTH('pim.CentralAdmins','TierLevel') IS NOT NULL
              ALTER TABLE pim.CentralAdmins DROP COLUMN TierLevel;
      which is a genuine data-destroying statement. It is inert on a store that has no such column,
      and the deploy-host path only ever ran these files when the tables were ABSENT -- an implicit
      precondition that the in-cloud path has to make explicit, because it would otherwise run them
      on every bootstrap, including against a populated customer database.

      🔑 SO WHAT THIS FUNCTION IS FOR: the verbs that are destructive EVEN ON AN EMPTY STORE, where
      the table count cannot protect anything. Dropping the database, dropping a schema, restoring
      over it, renaming objects -- none of those belongs in a shipped schema file at any time.

      REFUSED: DROP DATABASE, DROP SCHEMA, DROP TABLE, TRUNCATE, DELETE, UPDATE, MERGE, sp_rename,
               BACKUP / RESTORE DATABASE.
      ALLOWED: CREATE / ALTER of schemas, tables, indexes, views, procedures -- including
               ALTER TABLE ... DROP COLUMN, which can remove nothing from a store with no rows, and
               which the shipped upgrade path legitimately uses.
      🪤 INSERT is allowed, unlike in the user-DDL guard: a schema file legitimately seeds a lookup
      or a version row, and on an empty store that ADDS rather than overwrites.

      🪤 COMMENTS ARE STRIPPED FIRST. Without that, the (now retired) sql/local-schema.sql was refused for
      "BACKUP/RESTORE" because line 4 of its header prose contains the word "backup". A guard that
      fires on a comment gets switched off by the next person who hits it, and then protects nothing.

      Returns @{ ok; violations }.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql)
    $code = "$Sql" -replace '(?s)/\*.*?\*/', ' ' -replace '(?m)--.*$', ' '
    $bad = @(
        @{ rx = '(?i)\bDROP\s+TABLE\b';        why = 'DROP TABLE' }
        @{ rx = '(?i)\bDROP\s+SCHEMA\b';       why = 'DROP SCHEMA' }
        @{ rx = '(?i)\bDROP\s+DATABASE\b';     why = 'DROP DATABASE' }
        @{ rx = '(?i)\bTRUNCATE\b';            why = 'TRUNCATE' }
        @{ rx = '(?i)\bDELETE\s+FROM\b';       why = 'DELETE' }
        @{ rx = '(?i)\bUPDATE\s+\w';           why = 'UPDATE' }
        @{ rx = '(?i)\bMERGE\s+\w';            why = 'MERGE' }
        @{ rx = '(?i)\bsp_rename\b';           why = 'sp_rename' }
        @{ rx = '(?i)\bBACKUP\s+(DATABASE|LOG)\b|\bRESTORE\s+DATABASE\b'; why = 'BACKUP/RESTORE' }
    )
    $v = @()
    foreach ($b in $bad) { if ($code -match $b.rx) { $v += $b.why } }
    return @{ ok = (@($v).Count -eq 0); violations = @($v) }
}

function Get-PimSqlBootstrapVerifyQuery {
    # Read the result back. A bootstrap that does not verify is a claim.
    [CmdletBinding()] param([string[]]$Names = @())
    $safe = @($Names | Where-Object { "$_".Trim() } | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" })
    if (-not $safe.Count) { return $null }
    return @"
SELECT p.name AS name, CONVERT(varchar(100), p.sid, 1) AS sid,
       ISNULL(STUFF((SELECT ',' + r.name FROM sys.database_role_members m
              JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
              WHERE m.member_principal_id = p.principal_id ORDER BY r.name FOR XML PATH('')),1,1,''),'') AS roles
FROM sys.database_principals p
WHERE p.type IN ('E','X') AND p.name IN ($($safe -join ','))
"@
}
