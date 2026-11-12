#Requires -Version 7.0
<#
    dbinit-job-entry.ps1 -- the environment sets up its OWN database, from inside.

    🔑 WHY THIS RUNS IN A CONTAINER AND NOT ON A DEPLOY HOST.
    A policy-restricted tenant creates Azure SQL with publicNetworkAccess disabled. That is correct
    -- SQL needs no inbound path from the internet -- but it means a deploy host OUTSIDE the VNet
    has no route to the server at all, and the deploy used to connect from there to create the
    contained users. Making the deploy identity the Entra admin only moved the problem: it handed
    administration to the one identity that cannot reach the server.

    This job is inside the VNet, so it reaches SQL over the private endpoint, and it carries the
    USER-ASSIGNED managed identity that IS the server's Entra admin. Network access and admin
    rights, both from inside. Nothing public, no jump box, no credential anywhere.

    🪤 THE CONTAINER CARRIES SEVERAL IDENTITIES (system-assigned, the ACR pull identity, and the SQL
    admin), and IMDS returns the SYSTEM one unless asked otherwise -- which here is the identity
    with NO database rights at all. PIM_DBINIT_MI_CLIENT_ID names the one to use, and it is a client
    id, not a secret.

    Every decision -- which principals, what SID, the exact DDL -- is made by
    engine/_shared/PIM-SqlBootstrap.ps1 and proven offline in tests/Test-PimSqlBootstrap.ps1. This
    file only connects, executes and verifies.

    Exit 0 only when every requested principal was READ BACK with the right SID and roles.
#>
$ErrorActionPreference = 'Stop'

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$solRoot = Split-Path -Parent (Split-Path -Parent $here)     # SOLUTIONS/PIM4EntraPS

function Say ($m, $c = 'Gray') { try { Write-Host "  $m" -ForegroundColor $c } catch { [Console]::Out.WriteLine("  $m") } }
function Step($m) { try { Write-Host "[dbinit] $m" -ForegroundColor Cyan } catch { [Console]::Out.WriteLine("[dbinit] $m") } }

Step 'start'

# 🪤 DOT-SOURCED, NOT GUARDED WITH Get-Command. A `if (Get-Command X)` around a function this entry
# point never LOADS is the inert-capability class: the step reports "skipped" truthfully and
# forever, and reads as covered.
. (Join-Path $solRoot 'engine/_shared/PIM-Rest.ps1')
# QUIESCE-DIED-1 (1): a process liveness line every 5 min (never fails the job)
. (Join-Path $solRoot 'engine/_shared/PIM-Beat.ps1')
$pimBeat = Start-PimBeat; if ($pimBeat.started -or $pimBeat.reason -match 'could not') { Write-Host "[beat] $($pimBeat.reason)" }
. (Join-Path $solRoot 'engine/_shared/PIM-SqlStore.ps1')
. (Join-Path $solRoot 'engine/_shared/PIM-SqlBootstrap.ps1')
# PIM 100.156 B: the access catalog decides each principal's roles (Get-PimSqlComponentAccess) -- loaded BEFORE the plan.
. (Join-Path $solRoot 'engine/_shared/PIM-InstallNames.ps1')
. (Join-Path $solRoot 'engine/_shared/PIM-SqlAccess.ps1')
# DBINIT-STEP-FILTER (framework 8.18 amended; PIM 3.0.51): the step filter's rules live beside the schema quiesce they extend,
# and the "no open Support session before a re-sign" read is the support-access module's own state read.
. (Join-Path $solRoot 'engine/_shared/PIM-SchemaQuiesce.ps1')
. (Join-Path $solRoot 'engine/_shared/PIM-SupportJit.ps1')

# PIM_DBINIT_STEPS (per execution): unset / 'all' = every step, as before; 'grants' = ONLY the part that may run BESIDE a running
# PIM job (users, role membership, the access roles + grants; a re-sign of the access procedure only while no Support session is
# open). Every other step keeps waiting for the run end (SCHEMA-QUIESCE-818). Anything else is refused before anything is read.
$stepF = ConvertTo-PimDbInitStepFilter -Value "$($env:PIM_DBINIT_STEPS)"
if (-not $stepF.ok) { Say "REFUSED: $($stepF.reason)" 'Red'; exit 2 }
$grantsOnly = ($stepF.filter -eq 'grants')

$sqlServer = "$($env:PIM_SqlServer)".Trim()
$sqlDb     = "$($env:PIM_SqlDatabase)".Trim(); if (-not $sqlDb) { $sqlDb = 'PimPlatform' }
$miCid     = "$($env:PIM_DBINIT_MI_CLIENT_ID)".Trim()
$rawPrin   = "$($env:PIM_DBINIT_PRINCIPALS)".Trim()

if (-not $sqlServer) { Say 'PIM_SqlServer is not set -- refusing to guess which database to set up.' 'Red'; exit 2 }
if (-not $rawPrin)   { Say 'PIM_DBINIT_PRINCIPALS is not set -- nothing to create. That is a configuration error, not an empty job.' 'Red'; exit 2 }

# The identity to authenticate AS. Without it IMDS hands back the system-assigned identity, which
# is precisely the one this job is about to grant rights to -- and which has none yet.
if ($miCid) {
    $global:PIM_ManagedIdentityClientId = $miCid
    Say "authenticating as user-assigned identity $miCid (the SQL Entra admin)"
} else {
    Say 'PIM_DBINIT_MI_CLIENT_ID is not set -- falling back to the system-assigned identity.' 'Yellow'
    Say 'That identity is usually NOT the SQL admin, so expect "Login failed for user" rather than a rights error.' 'Yellow'
}

$principals = $null
try { $principals = @($rawPrin | ConvertFrom-Json) } catch {
    Say "PIM_DBINIT_PRINCIPALS is not valid JSON: $($_.Exception.Message)" 'Red'; exit 2
}

$plan = Get-PimSqlBootstrapPlan -Principals $principals
foreach ($p in @($plan.problems)) { Say "PROBLEM: $p" 'Red' }
if (@($plan.problems).Count) {
    # 🔒 REFUSE THE WHOLE RUN. A partially-created set of users is the worst outcome: the deploy
    # reports success and one app cannot log in, which is found days later.
    Say 'refusing to create a PARTIAL set of database users.' 'Red'
    exit 1
}
# OPEN-06: the updater writes this job on EVERY install with PIM_DBINIT_PRINCIPALS = [] (no user to create). An EMPTY list
# skips only the user step; the schema, the access model, the feature gates, the Manager access and the update record still
# run when they are asked for. Nothing at all asked for = exit 0. (An UNSET list is still a configuration error, exit 2.)
$otherWork = @('PIM_DBINIT_SCHEMA', 'PIM_DBINIT_DROP_USERS', 'PIM_DBINIT_SQL_ACCESS', 'PIM_DBINIT_FEATURE_GATES', 'PIM_DBINIT_FEATURE_DISABLE', 'PIM_DBINIT_MANAGER_ACCESS', 'PIM_DBINIT_UPDATE_SEED') |
             Where-Object { $v = "$([Environment]::GetEnvironmentVariable($_))".Trim(); $v -and ($_ -ne 'PIM_DBINIT_SCHEMA' -or $v -in @('1', 'true', 'yes', 'TRUE', 'Yes')) }
if (-not @($plan.users).Count) {
    if (-not @($otherWork).Count) { Say 'no principals to create and nothing else asked for.' 'Yellow'; exit 0 }
    Say "no principals to create -- the user step is skipped; continuing with: $(@($otherWork) -join ', ')" 'DarkGray'
}

# ---- DBINIT-STEP-FILTER: which steps this execution runs -------------------------------------------------------------------
# The steps it would run without a filter (the SAME conditions as the blocks below), and the ones a starter asked for on
# purpose. Without a filter every asked step runs ($runStep is always true -- today's behaviour). With 'grants' only the grants
# kind runs; a default step of the job's definition (base schema, statistics, templates) is held with one line, and an explicit
# ask that is not a grant (feature gates, Manager access, the update ring record, run 2) refuses the whole run, before connecting.
$djTrue = @('1', 'true', 'yes', 'TRUE', 'Yes')
$askedSteps = New-Object System.Collections.Generic.List[string]; $explicitSteps = New-Object System.Collections.Generic.List[string]
if (@($plan.users).Count) { [void]$askedSteps.Add('users') }
if (@($plan.users | Where-Object { $_.signinOwner }).Count) { [void]$askedSteps.Add('signin-owner') }
if ("$($env:PIM_DBINIT_DROP_USERS)".Trim()) { [void]$askedSteps.Add('drop-old-users'); [void]$explicitSteps.Add('drop-old-users') }

if ("$($env:PIM_DBINIT_SCHEMA)".Trim() -in $djTrue) { [void]$askedSteps.Add('schema') }
[void]$askedSteps.Add('statistics')
if ("$($env:PIM_DBINIT_SQL_ACCESS)".Trim()) {
    foreach ($s in @('access-prerequisites', 'access', 'access-facts')) { [void]$askedSteps.Add($s) }
    $djR2 = $false; try { $djSa = "$($env:PIM_DBINIT_SQL_ACCESS)".Trim() | ConvertFrom-Json; $djR2 = [bool]($djSa.PSObject.Properties['run2'] -and [bool]$djSa.run2) } catch { $djR2 = $false }
    if ($djR2) { [void]$askedSteps.Add('access-run2'); [void]$explicitSteps.Add('access-run2') }
}
[void]$askedSteps.Add('policy-templates'); [void]$askedSteps.Add('mail-templates')
if ("$($env:PIM_DBINIT_FEATURE_GATES)$($env:PIM_DBINIT_FEATURE_DISABLE)".Trim()) { [void]$askedSteps.Add('feature-gates'); [void]$explicitSteps.Add('feature-gates') }
if ("$($env:PIM_DBINIT_MANAGER_ACCESS)".Trim()) { [void]$askedSteps.Add('manager-access'); [void]$explicitSteps.Add('manager-access') }
if ("$($env:PIM_DBINIT_UPDATE_SEED)".Trim()) { [void]$askedSteps.Add('update-seed'); [void]$explicitSteps.Add('update-seed') }
$stepPlan = Get-PimSchemaQuiesceDbInitPlan -Filter $stepF.filter -Asked @($askedSteps.ToArray()) -Explicit @($explicitSteps.ToArray())
$runStep = { param($id) (-not $grantsOnly) -or (@($stepPlan.run) -contains "$id") }
if ($grantsOnly) {
    foreach ($l in @($stepPlan.lines)) { Say $l $(if ($stepPlan.refused) { 'Red' } else { 'DarkGray' }) }
    if ($stepPlan.refused) { exit 2 }
    if (-not @($stepPlan.run).Count) { Say 'grants only: no grants step is asked for this run -- nothing connected to or changed.' 'Yellow'; exit 0 }
}

Step ("plan: " + $(if (@($plan.users).Count) { (@($plan.users) | ForEach-Object { $_.name }) -join ', ' } else { '(no users)' }))

# 🔴 BLAST-RADIUS GUARD, BEFORE ANY CONNECTION IS OPENED.
# This runs unattended, as a database admin, against a customer's production store. Its legitimate
# footprint is principals and role membership -- never a table, never a row. That is enforced here
# rather than asserted: every statement is checked, and anything data-destructive refuses the run.
foreach ($u in @($plan.users)) {
    $safe = Test-PimSqlBootstrapDdlSafe -Ddl $u.ddl
    if (-not $safe.ok) {
        Say "REFUSING TO RUN: the DDL for '$($u.name)' contains $(@($safe.violations) -join ', ')." 'Red'
        Say 'This job may only create principals and role membership. Nothing here should ever touch data.' 'Red'
        exit 1
    }
}
Say "blast-radius check: $(@($plan.users).Count) statement set(s), none touch tables, rows or schema contents" 'Green'

# ---- THE BASE SCHEMA, for the same reason the users are created here ---------------------------
# 🔑 A PRIVATE SQL SERVER HAS NO ROUTE FROM THE DEPLOY HOST, AND THAT APPLIES TO THE SCHEMA TOO.
# Invoke-PimUpdate applies sql/platform-schema.sql on a first install, from
# the deploy host, over a connection that simply cannot be opened in this topology. So the deploy
# would stand up a perfectly healthy Manager against an EMPTY database -- the §50/BUG-50 shape the
# updater's own comments call the worst one: every environment green, none of them functional.
# The files are applied here instead, from inside, in the same pass that creates the users.
# 🪤 ORDER MATTERS: users FIRST, schema SECOND. The apps authenticate as the contained users, and
# the conformance work the nightly in-cloud updater does later runs as them.
$schemaFiles = @()
if ("$($env:PIM_DBINIT_SCHEMA)".Trim() -in @('1','true','yes','TRUE','Yes') -and (& $runStep 'schema')) {   # DBINIT-STEP-FILTER: never under 'grants'
    # 2026-09-18 (IMP-46): sql/local-schema.sql (only the dead pim.LocalAdmins / pim.LocalResources)
    # was retired. The one shipped base-schema file is platform-schema.sql; the verify below still
    # requires tables in 'pim' after it runs (it creates pim.CentralAdmins + pim.TenantRoleProjection).
    foreach ($rel in @('sql/platform-schema.sql')) {
        $f = Join-Path $solRoot $rel
        if (-not (Test-Path -LiteralPath $f)) {
            Say "PIM_DBINIT_SCHEMA is set but '$rel' is missing from this image -- the store cannot be created." 'Red'
            exit 2
        }
        $sqlText = [IO.File]::ReadAllText($f)
        # 🔴 THE SAME BLAST-RADIUS QUESTION, ASKED OF A BIGGER FOOTPRINT, BEFORE CONNECTING.
        # Creating a table that does not exist cannot lose anything. DELETE/UPDATE/TRUNCATE/DROP
        # TABLE can, and none of them belongs in a shipped schema file -- so any of them refuses the
        # run rather than being executed and reported.
        $sSafe = Test-PimSqlSchemaFileSafe -Sql $sqlText
        if (-not $sSafe.ok) {
            Say "REFUSING TO RUN: '$rel' contains $(@($sSafe.violations) -join ', ')." 'Red'
            Say 'A shipped schema file may create and extend; it may never remove or rewrite existing data.' 'Red'
            exit 1
        }
        $schemaFiles += @{ rel = $rel; sql = $sqlText }
    }
    Say "blast-radius check: $(@($schemaFiles).Count) schema file(s), none remove or rewrite existing data" 'Green'
}

# A dry run prints the exact SQL and stops. Nothing is opened, nothing is executed.
if ("$($env:PIM_DBINIT_WHATIF)".Trim() -in @('1','true','yes','TRUE','Yes')) {
    Step 'WHATIF -- the exact SQL that WOULD run, and nothing else'
    foreach ($u in @($plan.users)) {
        Write-Host ""
        Write-Host "---- $($u.name)  ($($u.sid)) ----" -ForegroundColor Cyan
        Write-Host $u.ddl
    }
    foreach ($s in @($schemaFiles)) {
        Write-Host ""
        Write-Host "---- $($s.rel) ----" -ForegroundColor Cyan
        Write-Host $s.sql
    }
    Step 'WHATIF -- nothing was connected to or changed.'
    exit 0
}

$cs = "Server=tcp:$sqlServer,1433;Database=$sqlDb;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60"
$conn = $null
try {
    $conn = New-PimSqlConnection -ConnectionString $cs
    $conn.Open()
    Say "connected to $sqlServer/$sqlDb" 'Green'
} catch {
    Say "could not connect: $($_.Exception.Message)" 'Red'
    Say 'If this is "Login failed for user <token-identified principal>", the identity above is not the' 'Yellow'
    Say 'server Entra admin. If it is a timeout, there is no route -- check the private endpoint and its DNS.' 'Yellow'
    exit 1
}

$failed = 0
try {
    foreach ($u in @($plan.users)) {
        try {
            $cmd = $conn.CreateCommand(); $cmd.CommandText = $u.ddl; $cmd.CommandTimeout = 120
            [void]$cmd.ExecuteNonQuery()
            Say "applied $($u.name) -> $($u.sid) [$(@($u.roles) -join ', ')]" 'Green'
        } catch {
            Say "FAILED $($u.name): $($_.Exception.Message)" 'Red'; $failed++
        }
    }

    # ---- VERIFY, never assume. Read every user back: SID and role membership both. -------------
    # A user that authenticates and can read nothing is harder to diagnose than one that cannot log
    # in at all, so the roles are checked too.
    $seen = @{}
    if (@($plan.users).Count) {   # OPEN-06: an empty principal list has no user to read back
    Step 'verify'
    $q = Get-PimSqlBootstrapVerifyQuery -Names (@($plan.users) | ForEach-Object { $_.name })
    $cmd = $conn.CreateCommand(); $cmd.CommandText = $q
    $r = $cmd.ExecuteReader()
    while ($r.Read()) { $seen[[string]$r['name']] = @{ sid = [string]$r['sid']; roles = [string]$r['roles'] } }
    $r.Close()
    }

    foreach ($u in @($plan.users)) {
        $got = $seen[$u.name]
        if (-not $got) { Say "MISSING after apply: $($u.name)" 'Red'; $failed++; continue }
        if ("$($got.sid)" -ine $u.sid) { Say "WRONG SID for $($u.name): $($got.sid), expected $($u.sid)" 'Red'; $failed++; continue }
        $want = (@($u.roles) | Sort-Object) -join ','
        $have = (@("$($got.roles)".Split(',') | Where-Object { "$_".Trim() }) | Sort-Object) -join ','
        # PIM 100.156 B: EVERY wanted role must be held; an EXTRA one is reported, never a failure -- this job only adds,
        # and an existing install still carries the broad roles until the cut-over's second run takes them away.
        $heldR = @("$($got.roles)".Split(',') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $miss = @(@($u.roles) | Where-Object { $heldR -notcontains "$_" })
        if ($miss.Count) { Say "WRONG ROLES for $($u.name): '$have', expected '$want' (missing $($miss -join ', '))" 'Red'; $failed++; continue }
        $extra = @($heldR | Where-Object { @($u.roles) -notcontains "$_" })
        if ($extra.Count) { Say "  $($u.name) also holds $($extra -join ', ') (left as it is -- this job never takes a role away)" 'Yellow' }
        Say "verified $($u.name) -> $($got.sid) [$have]" 'Green'
    }

    # ---- SIGNIN-OWNER (PIM item 21, incident 2026-11-08 08:46Z) -----------------------------------------------------------
    # The principal the list marks signinOwner = true (the web identity: the sign-in front keeps its key ring in schema
    # 'signin') OWNS that schema and holds CREATE TABLE. Converged on every run, read back; the guard allows exactly the three
    # statements Get-PimSigninOwnerSqlPlan makes. A grants-kind step (it may run beside a running job).
    $soUsers = @($plan.users | Where-Object { $_.signinOwner })
    if (-not $failed -and $soUsers.Count -gt 1) { Say "REFUSED signin-owner: $($soUsers.Count) principals are marked signinOwner ($(@($soUsers | ForEach-Object { $_.name }) -join ', ')) -- a schema has ONE owner" 'Red'; $failed++ }
    elseif (-not $failed -and $soUsers.Count -eq 1 -and (& $runStep 'signin-owner')) {
        Step 'signin-owner'
        $so = $soUsers[0].name
        $readSo = {
            $c2 = $conn.CreateCommand(); $c2.CommandText = (Get-PimSigninOwnerReadQuery -User $so); $rd = $c2.ExecuteReader(); [void]$rd.Read()
            $o = if ($rd.IsDBNull(0)) { '' } else { "$($rd['owner'])" }; $ct = ([int]$rd['createTable'] -gt 0); $rd.Close()
            [pscustomobject]@{ owner = $o; createTable = $ct }
        }
        try {
            $now = & $readSo
            $soPlan = @(Get-PimSigninOwnerSqlPlan -User $so -Owner $now.owner -CreateTableGranted $now.createTable)
            $soSafe = Test-PimSigninOwnerSqlSafe -Statements $soPlan
            if (-not $soSafe.ok) { Say "REFUSING signin-owner: unexpected statement(s) $(@($soSafe.violations) -join ' | ')" 'Red'; $failed++ }
            else {
                foreach ($s in $soPlan) { $c3 = $conn.CreateCommand(); $c3.CommandText = $s; $c3.CommandTimeout = 120; [void]$c3.ExecuteNonQuery(); Say "applied: $s" 'Green' }
                $back = & $readSo
                if ($back.owner -eq $so -and $back.createTable) { Say "verified: schema signin owned by $so, CREATE TABLE held$(if (-not $soPlan.Count) { ' (nothing to change)' }) (was owner '$($now.owner)')" 'Green' }
                else { Say "signin-owner NOT verified: owner '$($back.owner)', CREATE TABLE $($back.createTable) (wanted $so + True)" 'Red'; $failed++ }
            }
        } catch { Say "FAILED signin-owner for ${so}: $($_.Exception.Message)" 'Red'; $failed++ }
    }

    # ---- DROP-OLD-USERS (PIM item 21 (b), framework 12.11c ruling (b)) ---------------------------------------------------
    # The OLD database users of moved roles (their system identities), asked by app id in PIM_DBINIT_DROP_USERS. A REMOVAL step
    # (never under 'grants'), AFTER signin-owner (a schema is moved before its old owner could be dropped). Get-PimDropUsersPlan
    # refuses anything this job's own list uses, any id-pim-* user, a built-in or non-Entra user, a schema owner, a user with an
    # explicit permission; the only statement is DROP USER [name]; each is read back as gone. A refusal is reported, the rest go.
    $duRaw = "$($env:PIM_DBINIT_DROP_USERS)".Trim()
    if (-not $failed -and $duRaw -and (& $runStep 'drop-old-users')) {
        Step 'drop-old-users'
        try {
            $duIds = @($duRaw | ConvertFrom-Json | ForEach-Object { "$_" })
            $readUsers = { $c4 = $conn.CreateCommand(); $c4.CommandText = (Get-PimDropUsersReadQuery); $rd = $c4.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($rd.Read()) { $rows.Add([pscustomobject]@{ name = "$($rd['name'])"; sid = "$($rd['sid'])"; type = "$($rd['type'])"; ownsSchema = [int]$rd['ownsSchema']; explicitPerms = [int]$rd['explicitPerms'] }) }; $rd.Close(); $rows.ToArray() }
            $duPlan = Get-PimDropUsersPlan -AppIds $duIds -Existing @(& $readUsers) -KeepSids @($plan.users | ForEach-Object { $_.sid })
            foreach ($r in @($duPlan.refused)) { Say "kept (refused): $r" 'Yellow' }
            foreach ($a in @($duPlan.absent)) { Say "already gone: the user of app $a" 'DarkGray' }
            $duSql = @($duPlan.drop | ForEach-Object { "DROP USER [$_]" })
            $duSafe = Test-PimDropUsersSqlSafe -Statements $duSql
            if (-not $duSafe.ok) { Say "REFUSING drop-old-users: unexpected statement(s) $(@($duSafe.violations) -join ' | ')" 'Red'; $failed++ }
            else {
                foreach ($s in $duSql) { $c5 = $conn.CreateCommand(); $c5.CommandText = $s; $c5.CommandTimeout = 120; [void]$c5.ExecuteNonQuery(); Say "applied: $s" 'Green' }
                $left = @(& $readUsers | ForEach-Object { $_.name })
                $still = @($duPlan.drop | Where-Object { $left -contains $_ })
                if ($still.Count) { Say "drop-old-users NOT verified: still there: $($still -join ', ')" 'Red'; $failed++ }
                elseif ($duPlan.drop.Count) { Say "verified: dropped $($duPlan.drop -join ', ')" 'Green' }
            }
        } catch { Say "FAILED drop-old-users: $($_.Exception.Message)" 'Red'; $failed++ }
    }

    # ---- THE BASE SCHEMA, on the same connection, as the server's Entra admin -------------------
    # Only after the users verify: if the principals are wrong there is no point creating tables
    # nothing can read.
    if (-not $failed -and @($schemaFiles).Count) {
        Step 'base schema'
        # 🔴 THE PRECONDITION THAT MAKES THIS SAFE, CHECKED AS A FACT RATHER THAN ASSUMED.
        # The deploy-host path applies these files ONLY when the tables are absent. That was an
        # implicit precondition of WHERE it ran, and moving the work in here would have dropped it:
        # this job runs on every deploy, so it would re-apply the shipped schema to a populated
        # customer database. sql/platform-schema.sql line 91 is
        #     IF COL_LENGTH('pim.CentralAdmins','TierLevel') IS NOT NULL
        #         ALTER TABLE pim.CentralAdmins DROP COLUMN TierLevel;
        # -- inert on a store that has never had that column, and a real column drop on one that
        # has. So: a store that already has tables is LEFT ALONE, and conformance stays with the
        # nightly in-cloud updater, which owns drift and refuses destructive migrations by design.
        $c = $conn.CreateCommand()
        $c.CommandText = "SELECT COUNT(*) FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id WHERE s.name IN ('pim','platform')"
        $existing = [int]$c.ExecuteScalar()
        if ($existing -gt 0) {
            Say "store already has $existing table(s) -- NOT re-applying the shipped schema." 'Yellow'
            Say 'Schema drift on an existing store is the updater''s job; this bootstrap only creates.' 'DarkGray'
            $schemaFiles = @()
        }
    }
    if (-not $failed -and @($schemaFiles).Count) {
        foreach ($s in @($schemaFiles)) {
            try {
                # 🪤 SPLIT ON GO. It is a batch separator understood by tools, not a T-SQL keyword --
                # sent to the server verbatim it is a syntax error, and the whole file fails on a
                # line that looks correct.
                $n = 0
                foreach ($batch in ($s.sql -split '(?im)^\s*GO\s*$')) {
                    if (-not "$batch".Trim()) { continue }
                    $c = $conn.CreateCommand(); $c.CommandText = $batch; $c.CommandTimeout = 300
                    [void]$c.ExecuteNonQuery(); $n++
                }
                Say "applied $($s.rel) ($n batch(es))" 'Green'
            } catch {
                Say "FAILED $($s.rel): $($_.Exception.Message)" 'Red'; $failed++
            }
        }
        # VERIFY: the shipped files are idempotent, so "it ran" is not "the store exists". Read the
        # schemas back -- an empty database that reported success is the failure this whole path
        # exists to prevent (BUG-50: every environment green, none of them functional).
        if (-not $failed) {
            $c = $conn.CreateCommand()
            $c.CommandText = "SELECT COUNT(*) FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id WHERE s.name = 'pim'"
            $tables = [int]$c.ExecuteScalar()
            if ($tables -lt 1) {
                Say "the schema files applied but the 'pim' schema has NO tables -- the store was not created." 'Red'
                $failed++
            } else {
                Say "verified: $tables table(s) in schema 'pim'" 'Green'
            }
        }
    }
    # ---- STATISTICS (framework 12.27 SQL-STATS) ----------------------------------------------------
    # AUTO_UPDATE_STATISTICS_ASYNC ON + pim.usp_RefreshStatistics (WITH EXECUTE AS OWNER), as the server's admin: real SQL
    # refuses both to the least-privilege updater, so this admin job sets them (and the access install below does too, the
    # same idempotent call). BEFORE the access block, so its converge grants the job roles EXECUTE on the procedure. Own
    # statements on this connection, no transaction; the async setting is read back. A refusal is a WARNING, never a failed
    # job ($failed is not touched).
    if (-not $failed -and (& $runStep 'statistics')) {   # DBINIT-STEP-FILTER: a procedure the pipeline calls -- never under 'grants'
        Step 'statistics'
        $sq = { param($csx, $sql) $c3 = $conn.CreateCommand(); $c3.CommandText = $sql; $c3.CommandTimeout = 60
                $rd3 = $c3.ExecuteReader(); $rows3 = New-Object System.Collections.Generic.List[object]
                while ($rd3.Read()) { $o3 = [ordered]@{}; for ($i3 = 0; $i3 -lt $rd3.FieldCount; $i3++) { $o3[$rd3.GetName($i3)] = $(if ($rd3.IsDBNull($i3)) { $null } else { $rd3.GetValue($i3) }) }; $rows3.Add([pscustomobject]$o3) }
                $rd3.Close(); $rows3.ToArray() }
        $sx = { param($csx, $sql) $c3 = $conn.CreateCommand(); $c3.CommandText = $sql; $c3.CommandTimeout = 60; [void]$c3.ExecuteNonQuery() }
        $st2 = Initialize-PimSqlStatistics -ConnectionString 'dbinit' -Query $sq -Exec $sx -Admin
        Say $st2.async.message $(if ($st2.async.ok) { 'Green' } else { 'Yellow' })
        Say $(if ($st2.procedure) { 'statistics: pim.usp_RefreshStatistics is in place' } else { "statistics: pim.usp_RefreshStatistics NOT in place: $($st2.procedureError)" }) $(if ($st2.procedure) { 'Green' } else { 'Yellow' })
        # SQL-STATS-PROOF (framework 12.27 point 5): the heartbeat's Database read, created by the same admin call
        Say $(if ($st2.dbStats) { 'statistics: pim.usp_DatabaseStats is in place' } else { "statistics: pim.usp_DatabaseStats NOT in place: $($st2.dbStatsError)" }) $(if ($st2.dbStats) { 'Green' } else { 'Yellow' })
    }
    # ---- LEAST-PRIVILEGE ACCESS (framework §12.23 P4/P9, PIM 100.156) ------------------------------
    # The ADMIN half of the access model, from inside, as the server's Entra admin: the signed procedure, its 2099
    # in-database certificate (private key removed), pim_updater + EXECUTE, the updater's own DDL user, then one
    # converge. ADDITIVE (no fixed role is taken away here). SETUP TURNS IT ON for every new private-SQL install (PIM
    # 100.156 B: Setup-PimContainers / Deploy-PimUpdateJob stamp it on this job); unset = off, as before:
    # PIM_DBINIT_SQL_ACCESS = '{"updaterUserName":"ca-pim-update","updaterAppId":"<client id>"}' (both optional). The
    # prerequisites (platform schema + demo tables) come first, so the signer controls every product schema and the web
    # app never needs DDL. After this, every update is applied by the updater alone -- nothing routine needs the admin group.
    if (-not $failed -and "$($env:PIM_DBINIT_SQL_ACCESS)".Trim()) {
        Step 'least-privilege access'
        try {
            $sa = "$($env:PIM_DBINIT_SQL_ACCESS)".Trim() | ConvertFrom-Json
            $q = { param($csx, $sql) $c2 = $conn.CreateCommand(); $c2.CommandText = $sql; $c2.CommandTimeout = 120
                   $rd = $c2.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                   while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add([pscustomobject]$o) }
                   $rd.Close(); $rows.ToArray() }
            $x = { param($csx, $sql) $c2 = $conn.CreateCommand(); $c2.CommandText = $sql; $c2.CommandTimeout = 120; [void]$c2.ExecuteNonQuery() }
            if ($grantsOnly) {
                # DBINIT-STEP-FILTER (framework 8.18): beside a running PIM job -- roles, grants and users only, ADD only; no
                # prerequisites, no statistics or facts procedure (the pipeline calls those); the access procedure is re-signed
                # only when no Support session is open (read here, through the support module's own state procedure).
                $ss = { param($sqlText) $c4 = $conn.CreateCommand(); $c4.CommandText = $sqlText; $c4.CommandTimeout = 60; $c4.ExecuteScalar() }
                $sup = Get-PimSupportJitState -Sql $ss
                $ag = Invoke-PimSqlAccessGrantsOnly -Query $q -Exec $x -UpdaterUserName "$($sa.updaterUserName)" -UpdaterAppId "$($sa.updaterAppId)" -SupportState $sup -SetupGate:("$($sa.mode)" -eq 'setup')
                if ($ag.skipped) { Say "grants only: least-privilege access NOT converged: $($ag.reason)" 'Yellow' }
                else {
                    Say "grants only: re-sign $($ag.resign) -- $($ag.resignReason)" $(if ($ag.resign -eq 'held') { 'Yellow' } else { 'DarkGray' })
                    if ($ag.converge -and $ag.converge.applied) { Say ("grants only: $($ag.converge.statements) statement(s) converged (added only); users $(@($ag.converge.users) -join ', ')") 'Green' }
                    elseif ($ag.converge) { Say "grants only: nothing converged: $($ag.converge.reason)" 'Yellow' }
                }
            } else {
            $ar = Invoke-PimSqlAccessInstall -Query $q -Exec $x -UpdaterUserName "$($sa.updaterUserName)" -UpdaterAppId "$($sa.updaterAppId)" -WithPrerequisites -SetupGate:("$($sa.mode)" -eq 'setup')
            if ($ar.skipped) { Say "least-privilege access NOT installed: $($ar.reason)" 'Yellow' }
            else {
            Say ("access model installed: signer $($ar.signer) (expires $($ar.signerExpiry)), " +
                 "$($ar.converge.statements) statement(s) converged; users $(@($ar.converge.users) -join ', ')") 'Green'
            # framework 12.23 P8 EXCEPTION (owner 2026-10-18): "run2": true -- set by the UPDATER only on a later update, once
            # run 1 is old enough and the jobs ran green since -- takes the broad roles off the web app and the engine. Gated,
            # proven AS each user, and put back by itself when the proof fails (Invoke-PimSqlAccessRun2).
            if ($sa.PSObject.Properties['run2'] -and [bool]$sa.run2) {
                Step 'least-privilege access: run 2'
                $r2 = Invoke-PimSqlAccessRun2 -Query $q -Exec $x
                if ($r2.nothingToDo) { Say 'run 2: nothing to drop -- the runtime users hold no broad role' 'Green' }
                else {
                    Say ("run 2: dropped " + ((@($r2.dropped) | ForEach-Object { "$($_.member) from $($_.role)" }) -join ', ')) 'Green'
                    foreach ($p in @($r2.proofs)) { Say "run 2 PROOF $($p.user): $($p.detail) -> OK" 'Green' }
                }
            }
            }
            }   # DBINIT-STEP-FILTER: end of the full (no filter) admin run
        } catch {
            Say "FAILED least-privilege access: $($_.Exception.Message)" 'Red'; $failed++
        }
    }
    # ---- POLICY TEMPLATES (2026-09-12: "move templates to sql") ---------------------------------
    # The engine reads PIM policy templates from pim.Settings 'PolicyTemplates' ONLY. A fresh store gets
    # the shipped templates as its baseline HERE; on an existing store, templates still UNMODIFIED since the
    # shipped version they came from are upgraded to the new shipped content (audited), CUSTOMISED ones are
    # kept and flagged TEMPLATE-UPGRADE-AVAILABLE, new shipped templates are seeded (BUG-55 semantics,
    # Update-PimPolicyTemplateStore). Verified by read-back.
    if (-not $failed -and (& $runStep 'policy-templates')) {   # DBINIT-STEP-FILTER: rows the running jobs read -- never under 'grants'
        Step 'policy templates'
        try {
            . (Join-Path $solRoot 'engine/_shared/PIM-PolicyBaseline.ps1')
            . (Join-Path $solRoot 'engine/_shared/PIM-PolicyTemplateStore.ps1')
            $pt = Initialize-PimPolicyTemplateStore -ConnectionString $cs -TemplateDir (Join-Path $solRoot 'templates/policy')
            if ([int]$pt.count -le 0) { Say "no policy templates in SQL after seeding: $($pt.reason)" 'Red'; $failed++ }
            else { Say ("policy templates: {0} in SQL -- {1} (fingerprint {2})" -f $pt.count, $pt.reason, $pt.fingerprint) 'Green' }
        } catch {
            Say "FAILED policy templates: $($_.Exception.Message)" 'Red'; $failed++
        }
    }
    # ---- MAIL TEMPLATES (2026-09-13: ONE template store in SQL) ---------------------------------
    # pim.Settings 'MailTemplates' is seeded from the shipped templates/mail here; unedited entries follow a
    # newer shipped body, edited ones are kept, and the retired MailTemplateOverrides setting is merged in
    # ONCE (additive, audited). The engine and the Manager both read only this store.
    if (-not $failed -and (& $runStep 'mail-templates')) {   # DBINIT-STEP-FILTER: rows the running jobs read -- never under 'grants'
        Step 'mail templates'
        try {
            . (Join-Path $solRoot 'engine/_shared/PIM-MailTemplateStore.ps1')
            $mt = Update-PimMailTemplateStore -ConnectionString $cs -TemplateDir (Join-Path $solRoot 'templates/mail') -Actor 'dbinit'
            if ([int]$mt.count -le 0) { Say "no mail templates in SQL after seeding: $($mt.reason)" 'Red'; $failed++ }
            else { Say ("mail templates: {0} in SQL -- {1}" -f $mt.count, $mt.reason) 'Green' }
        } catch {
            Say "FAILED mail templates: $($_.Exception.Message)" 'Red'; $failed++
        }
    }
    # ---- FEATURE GATES, for the third time the same reason -------------------------------------
    # 🔑 A DISABLED GATE MAKES THE ENGINE A NO-OP THAT LOGS ok=True -- it is the difference between
    # "deployed" and "running". Set-PimFeatureBaseline applies them over a SQL connection FROM THE
    # DEPLOY HOST, which in this topology cannot be opened, and unlike the mail sender that step
    # HALTS the deploy. Users, schema and gates are the three things a store needs before anything
    # works, all three were host-side, and all three move in here together.
    if (-not $failed -and "$($env:PIM_DBINIT_FEATURE_GATES)$($env:PIM_DBINIT_FEATURE_DISABLE)".Trim()) {
        Step 'feature gates'
        $enable  = @("$($env:PIM_DBINIT_FEATURE_GATES)".Split(',')  | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $disable = @("$($env:PIM_DBINIT_FEATURE_DISABLE)".Split(',') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        try {
            # 🪤 USE THE SHIPPED HELPERS, DO NOT HAND-WRITE THE SQL. The first version of this block
            # wrote `SELECT [Value] FROM pim.Settings` -- the column is ValueJson, and there is an
            # UpdatedUtc to maintain. It failed the whole bootstrap on a customer deploy, which is
            # the expensive way to rediscover a schema that Set-PimSqlSetting / Get-PimAllSqlSettings
            # in the very file this job already dot-sources have always known.
            # They open their own connection with the same identity -- $global:PIM_ManagedIdentityClientId
            # is already set above, so this is the same principal on the same private endpoint.
            # 🔒 MERGE OVER WHAT IS PERSISTED, NEVER REPLACE. A read failure must not be read as
            # "nothing persisted" -- that silently discards an operator's existing choices on the
            # next deploy (the ESTATE-14 class, and Set-PimFeatureBaseline refuses for the same
            # reason). A throw here FAILS the job rather than writing a map built from nothing.
            $cur = @{}
            $existing = Get-PimAllSqlSettings -ConnectionString $cs
            if ($existing -and $existing.ContainsKey('FeatureGates')) {
                $raw = $existing['FeatureGates']
                if ($raw -is [string]) { $raw = $raw | ConvertFrom-Json }
                if ($raw -and $raw.gates) {
                    foreach ($p in $raw.gates.PSObject.Properties) { $cur["$($p.Name)"] = [bool]$p.Value }
                }
            }
            foreach ($k in $enable)  { $cur[$k] = $true }
            foreach ($k in $disable) { $cur[$k] = $false }
            Set-PimSqlSetting -ConnectionString $cs -Name 'FeatureGates' -Value ([ordered]@{ gates = $cur })

            # VERIFY by reading back -- a write that silently did nothing looks exactly like one
            # that worked, and the symptom is an engine that runs and does nothing.
            $back = @{}
            $b = Get-PimAllSqlSettings -ConnectionString $cs
            if ($b -and $b.ContainsKey('FeatureGates')) {
                $bp = $b['FeatureGates']
                if ($bp -is [string]) { $bp = $bp | ConvertFrom-Json }
                if ($bp -and $bp.gates) { foreach ($p in $bp.gates.PSObject.Properties) { $back["$($p.Name)"] = [bool]$p.Value } }
            }
            $bad = @(@($enable | Where-Object { -not $back[$_] }) + @($disable | Where-Object { $back[$_] }))
            if (@($bad).Count) { Say "gates did NOT take effect: $(@($bad) -join ', ')" 'Red'; $failed++ }
            else { Say ("gates verified: " + (($back.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$(if ($_.Value) { 'ON' } else { 'off' })" }) -join ', ')) 'Green' }
        } catch {
            Say "FAILED feature gates: $($_.Exception.Message)" 'Red'; $failed++
        }
    }
    # ---- MANAGER ACCESS (who is a SuperAdmin), same route, same reason -------------------------
    # 🔴 THE ONE WHERE "NOT APPLIED" MEANS NOBODY CAN ADMINISTER ANYTHING. Set-PimManagerAccess
    # writes pim.Settings['ManagerAccess'] from the DEPLOY HOST, which a private store has no route
    # from -- the fourth thing in this deploy to need moving inside, after the users, the schema and
    # the feature gates. Without it the Manager falls back to env vars and the named SuperAdmins
    # simply are not SuperAdmins.
    if (-not $failed -and "$($env:PIM_DBINIT_MANAGER_ACCESS)".Trim()) {
        Step 'manager access'
        try {
            $incoming = @("$($env:PIM_DBINIT_MANAGER_ACCESS)".Trim() | ConvertFrom-Json)
            # 🔒 MERGE, and a read failure FAILS rather than being read as "nothing stored" -- the
            # host-side script refuses for the same reason ("refusing to overwrite an unread access
            # model"), and overwriting an operator's access model is not recoverable from here.
            $stored = @()
            $all = Get-PimAllSqlSettings -ConnectionString $cs
            if ($all -and $all.ContainsKey('ManagerAccess')) {
                $cur = $all['ManagerAccess']
                if ($cur -is [string]) { $cur = $cur | ConvertFrom-Json }
                if ($cur) { $stored = @(if ($cur.PSObject.Properties['managerAccess']) { $cur.managerAccess } else { $cur }) }
            }
            $byId = [ordered]@{}
            foreach ($s in @($stored))   { if ("$($s.identity)".Trim()) { $byId["$($s.identity)".ToLowerInvariant()] = $s } }
            foreach ($i in @($incoming)) {
                if (-not "$($i.identity)".Trim()) { continue }
                $ik = "$($i.identity)".ToLowerInvariant()
                $ne = [ordered]@{ identity = "$($i.identity)".Trim(); role = "$($i.role)".Trim() }
                # SEC-90: keep the Entra object id the Manager bound to this identity (never one from the deploy input)
                if ($byId.Contains($ik)) { $so = "$($byId[$ik].objectId)".Trim(); if ($so -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $ne['objectId'] = $so.ToLowerInvariant() } }
                $byId[$ik] = $ne
            }
            $final = @($byId.Values)

            # 🔴 NEVER LEAVE THE MODEL WITH NO SUPERADMIN -- the same refusal the host-side script
            # makes. That locks every human out of the tool that manages privileged access, and from
            # in here there is no operator to notice.
            $supers = @($final | Where-Object { "$($_.role)" -eq 'SuperAdmin' })
            if (-not $supers.Count) {
                Say 'the resulting access model has NO SuperAdmin -- refusing to write it.' 'Red'; $failed++
            } else {
                Set-PimSqlSetting -ConnectionString $cs -Name 'ManagerAccess' -Value ([ordered]@{ managerAccess = $final })
                # Read back: an access model that did not land is a Manager nobody can administer.
                $back = @()
                $b2 = Get-PimAllSqlSettings -ConnectionString $cs
                if ($b2 -and $b2.ContainsKey('ManagerAccess')) {
                    $bm = $b2['ManagerAccess']
                    if ($bm -is [string]) { $bm = $bm | ConvertFrom-Json }
                    if ($bm) { $back = @(if ($bm.PSObject.Properties['managerAccess']) { $bm.managerAccess } else { $bm }) }
                }
                $missing = @(@($incoming) | Where-Object { $w = "$($_.identity)".ToLowerInvariant(); -not @($back | Where-Object { "$($_.identity)".ToLowerInvariant() -eq $w }).Count })
                if (@($missing).Count) {
                    Say "access entries did NOT land: $((@($missing) | ForEach-Object { $_.identity }) -join ', ')" 'Red'; $failed++
                } else {
                    Say ("access verified: $(@($back).Count) entr(y/ies), $(@($back | Where-Object { "$($_.role)" -eq 'SuperAdmin' }).Count) SuperAdmin") 'Green'
                }
            }
        } catch {
            Say "FAILED manager access: $($_.Exception.Message)" 'Red'; $failed++
        }
    }
    # ---- THE UPDATE RING THE DEPLOY SET, same route, same reason (2026-10-08) --------------------
    # Deploy-PimUpdateJob records the ring it wrote onto the update job in pim.Settings['UpdateState'] (kind
    # 'deploy'), so a fresh install's header says "ring N -- no update run yet" instead of "not recorded". On a
    # private store that write cannot be made from the deploy host, so it is handed in here as
    # PIM_DBINIT_UPDATE_SEED. One implementation (Invoke-PimUpdateStateDeploySeed): a REAL run record is never
    # replaced, and a read failure writes nothing. A REPORTING record: its failure is a warning, never a failed job.
    if (-not $failed -and "$($env:PIM_DBINIT_UPDATE_SEED)".Trim()) {
        Step 'update ring record'
        try {
            . (Join-Path $solRoot 'engine/_shared/PIM-UpdateState.ps1')
            $sd = "$($env:PIM_DBINIT_UPDATE_SEED)".Trim() | ConvertFrom-Json
            $cfgUtc = "$($sd.configuredUtc)"
            if ($sd.configuredUtc -is [datetime]) { $cfgUtc = $sd.configuredUtc.ToUniversalTime().ToString('o') }
            $sr = Invoke-PimUpdateStateDeploySeed -ConnectionString $cs -Environment "$($sd.environment)" -Ring "$($sd.ring)" `
                      -Source "$($sd.source)" -InstalledVersion "$($sd.installedVersion)" -Hold ([bool]$sd.hold) -ConfiguredUtc $cfgUtc
            if ($sr.ok) { Say "update state: $($sr.reason)" 'Green' }
            else { Say "update state NOT recorded ($($sr.reason)) -- the update job records it on its first run" 'Yellow' }
        } catch {
            Say "update state NOT recorded: $($_.Exception.Message) -- the update job records it on its first run" 'Yellow'
        }
    }
} finally {
    try { $conn.Close() } catch { }
}

if ($failed) { Step "FAILED ($failed problem(s))"; exit 1 }
if ($grantsOnly) { Step "grants only: done ($(@($stepPlan.run) -join ', ')); every other step waits for the run end" }
Step 'done -- every principal created and verified'
exit 0
