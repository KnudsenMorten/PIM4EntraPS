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
. (Join-Path $solRoot 'engine/_shared/PIM-SqlStore.ps1')
. (Join-Path $solRoot 'engine/_shared/PIM-SqlBootstrap.ps1')

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
if (-not @($plan.users).Count) { Say 'no principals to create.' 'Yellow'; exit 0 }

Step ("plan: " + (@($plan.users) | ForEach-Object { $_.name }) -join ', ')

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
if ("$($env:PIM_DBINIT_SCHEMA)".Trim() -in @('1','true','yes','TRUE','Yes')) {
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
    Step 'verify'
    $q = Get-PimSqlBootstrapVerifyQuery -Names (@($plan.users) | ForEach-Object { $_.name })
    $seen = @{}
    $cmd = $conn.CreateCommand(); $cmd.CommandText = $q
    $r = $cmd.ExecuteReader()
    while ($r.Read()) { $seen[[string]$r['name']] = @{ sid = [string]$r['sid']; roles = [string]$r['roles'] } }
    $r.Close()

    foreach ($u in @($plan.users)) {
        $got = $seen[$u.name]
        if (-not $got) { Say "MISSING after apply: $($u.name)" 'Red'; $failed++; continue }
        if ("$($got.sid)" -ine $u.sid) { Say "WRONG SID for $($u.name): $($got.sid), expected $($u.sid)" 'Red'; $failed++; continue }
        $want = (@($u.roles) | Sort-Object) -join ','
        $have = (@("$($got.roles)".Split(',') | Where-Object { "$_".Trim() }) | Sort-Object) -join ','
        if ($want -ne $have) { Say "WRONG ROLES for $($u.name): '$have', expected '$want'" 'Red'; $failed++; continue }
        Say "verified $($u.name) -> $($got.sid) [$have]" 'Green'
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
    # ---- POLICY TEMPLATES (2026-09-12: "move templates to sql") ---------------------------------
    # The engine reads PIM policy templates from pim.Settings 'PolicyTemplates' ONLY. A fresh store gets
    # the shipped templates as its baseline HERE; on an existing store, templates still UNMODIFIED since the
    # shipped version they came from are upgraded to the new shipped content (audited), CUSTOMISED ones are
    # kept and flagged TEMPLATE-UPGRADE-AVAILABLE, new shipped templates are seeded (BUG-55 semantics,
    # Update-PimPolicyTemplateStore). Verified by read-back.
    if (-not $failed) {
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
    if (-not $failed) {
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
            foreach ($i in @($incoming)) { if ("$($i.identity)".Trim()) { $byId["$($i.identity)".ToLowerInvariant()] = [ordered]@{ identity = "$($i.identity)".Trim(); role = "$($i.role)".Trim() } } }
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
} finally {
    try { $conn.Close() } catch { }
}

if ($failed) { Step "FAILED ($failed problem(s))"; exit 1 }
Step 'done -- every principal created and verified'
exit 0
