#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.68 (b) -- the DEMO DATASET for the internal demo environment: a seeded, synthetic, tenant-scale
  dataset (thousands of users / groups / roles, months of activity, every health check green) that the Dashboard shows
  in place of the environment's own counters -- ONLY where the environment is flagged demo.

.DESCRIPTION
  Not to be confused with s98 "demo mode" (the read-only demo GUEST role, PIM-DemoMode.ps1). This is the data.

  🔒 Where it lives: its OWN schema, pimdemo (Meta, Principals, Assignments, Activity, Tenants) -- never a row in pim.Rows,
     pim.Settings or any table the engine reads. Every statement goes through Invoke-PimDemoSql, which opens the demo
     scope; PIM-SqlStore's Assert-PimSqlDemoScope refuses a statement naming pimdemo anywhere else. No engine entry and no
     scheduler loads this file, so the engine can never read -- let alone apply -- demo data (tests/Test-PimDemoData.ps1).
  🔒 Who turns it on: only tools/setup/Set-PimDemoMode.ps1 -Enable -Apply, which REFUSES unless the environment is proven
     to be the internal demo one (Get-PimDemoModeEligibility): a recorded update ring 0 or 1 (ring 2/3 = customers; not
     recorded = unsure = refused) AND a valid licence whose customer is an internal / demo licensee (a customer licence,
     no licence, or an unreadable one = refused).
  🔒 What shows it: the flag pimdemo.Meta DemoEnvironment = 'true' (written only by that script), honoured unless the
     environment variable PIM_DEMO_MODE says off. PIM_DEMO_MODE=on WITHOUT the flag does nothing.
  🔒 Marked: a discreet "Demo data" marker in the page footer and in every export while it is shown.
  🔒 Disable removes it completely: every pimdemo table and the schema are dropped.
  Names are generic (first name + a fictional company name as surname, contoso.example), never real people.
#>

$script:PimDemoSchema = 'pimdemo'
$script:PimDemoAllowedCustomerPattern = '(?i)\b(internal|demo)\b'
$script:PimDemoFirstNames = @('Avery', 'Blake', 'Casey', 'Dana', 'Eden', 'Finley', 'Gray', 'Harper', 'Indy', 'Jordan', 'Kai', 'Logan', 'Morgan', 'Noel', 'Oakley', 'Parker', 'Quinn', 'Reese', 'Sage', 'Taylor', 'Umber', 'Vale', 'Winter', 'Xen', 'Yael', 'Zion')
$script:PimDemoSurnames = @('Contoso', 'Fabrikam', 'Northwind', 'Tailspin', 'Adatum', 'Litware', 'Proseware', 'Woodgrove', 'Wingtip', 'Lucerne', 'Margie', 'Trey', 'Coho', 'Alpine', 'Relecloud', 'Humongous')
$script:PimDemoDepartments = @('Finance', 'HR', 'IT Operations', 'Security', 'Sales', 'Engineering', 'Legal', 'Support', 'Marketing', 'Facilities')
$script:PimDemoRoleNames = @('Global Reader', 'User Administrator', 'Groups Administrator', 'Helpdesk Administrator', 'Security Reader', 'Security Operator', 'Intune Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'Teams Administrator', 'Application Administrator', 'Cloud Device Administrator', 'Compliance Administrator', 'Billing Administrator', 'Reports Reader', 'License Administrator', 'Authentication Administrator', 'Privileged Role Administrator', 'Conditional Access Administrator', 'Azure Contributor', 'Azure Reader', 'Key Vault Secrets Officer', 'Storage Blob Data Reader', 'Virtual Machine Contributor')

function Test-PimDemoSqlNamesDemo { param([AllowEmptyString()][string]$Sql) return ("$Sql" -match '(?i)\[?\bpimdemo\b\]?\s*\.') }

function Invoke-PimDemoSql {
    <# The ONE way a demo statement runs: opens the demo scope for exactly this call. -Kind query | nonquery | scalar. -Invoker = test seam. #>
    param([Parameter(Mandatory)][ValidateSet('query', 'nonquery', 'scalar')][string]$Kind, [Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql, [hashtable]$Parameters = @{}, [scriptblock]$Invoker = $null)
    $prev = $global:PIM_DemoSqlScope
    $global:PIM_DemoSqlScope = $true
    try {
        if ($Invoker) { return (& $Invoker $Kind $Sql $Parameters) }
        switch ($Kind) {
            'query'    { return (Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql $Sql -Parameters $Parameters) }
            'nonquery' { return (Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $Sql -Parameters $Parameters -CommandTimeoutSec 300) }
            'scalar'   { return (Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql $Sql -Parameters $Parameters) }
        }
    } finally { $global:PIM_DemoSqlScope = $prev }
}

function Get-PimDemoSchemaDdl {
    <# PURE. The demo schema + tables (idempotent). #>
@'
IF SCHEMA_ID('pimdemo') IS NULL EXEC('CREATE SCHEMA pimdemo');
IF OBJECT_ID('pimdemo.Meta') IS NULL CREATE TABLE pimdemo.Meta (Name NVARCHAR(100) NOT NULL PRIMARY KEY, Value NVARCHAR(400) NULL, UpdatedUtc DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());
IF OBJECT_ID('pimdemo.Principals') IS NULL CREATE TABLE pimdemo.Principals (Id INT NOT NULL PRIMARY KEY, Kind NVARCHAR(20) NOT NULL, DisplayName NVARCHAR(200) NOT NULL, Upn NVARCHAR(200) NULL, Department NVARCHAR(60) NULL, Tier INT NULL);
IF OBJECT_ID('pimdemo.Assignments') IS NULL CREATE TABLE pimdemo.Assignments (Id INT NOT NULL PRIMARY KEY, PrincipalId INT NOT NULL, TargetId INT NOT NULL, AssignmentType NVARCHAR(20) NOT NULL, FirstSeenUtc DATETIME2 NOT NULL);
IF OBJECT_ID('pimdemo.Activity') IS NULL CREATE TABLE pimdemo.Activity (Id INT NOT NULL PRIMARY KEY, Kind NVARCHAR(30) NOT NULL, Ts DATETIME2 NOT NULL, StartUtc DATETIME2 NULL, EndUtc DATETIME2 NULL, PrincipalId INT NULL, TargetId INT NULL);
IF OBJECT_ID('pimdemo.Tenants') IS NULL CREATE TABLE pimdemo.Tenants (Id INT NOT NULL PRIMARY KEY, DisplayName NVARCHAR(200) NOT NULL);
'@
}

function Get-PimDemoRemoveSql {
    <# PURE. Removes the demo dataset COMPLETELY: every pimdemo table, then the schema. #>
@'
IF OBJECT_ID('pimdemo.Activity') IS NOT NULL DROP TABLE pimdemo.Activity;
IF OBJECT_ID('pimdemo.Assignments') IS NOT NULL DROP TABLE pimdemo.Assignments;
IF OBJECT_ID('pimdemo.Principals') IS NOT NULL DROP TABLE pimdemo.Principals;
IF OBJECT_ID('pimdemo.Tenants') IS NOT NULL DROP TABLE pimdemo.Tenants;
IF OBJECT_ID('pimdemo.Meta') IS NOT NULL DROP TABLE pimdemo.Meta;
IF SCHEMA_ID('pimdemo') IS NOT NULL EXEC('DROP SCHEMA pimdemo');
'@
}

function New-PimDemoDataset {
    <#
      PURE (seeded). The synthetic dataset: -Users people, -Groups delegation groups, -Roles roles (principals); eligible
      assignments (and a few time-bound active ones); -Months of activity (activations with windows, engine changes,
      approvals, review decisions, guard holds); -Tenants managed tenants. Same seed = same dataset.
    #>
    param([int]$Seed = 1068, [int]$Users = 2400, [int]$Groups = 600, [int]$Roles = 120, [int]$Months = 6, [int]$Tenants = 12, [datetime]$NowUtc = [datetime]::UtcNow)
    $rnd = New-Object System.Random($Seed)
    $now = $NowUtc.ToUniversalTime()
    $start = $now.AddMonths(-[Math]::Max(1, $Months))
    $span = ($now - $start).TotalMinutes
    $iso = { param([datetime]$d) $d.ToString('yyyy-MM-ddTHH:mm:ss') }
    $principals = New-Object System.Collections.Generic.List[object]
    $id = 0
    for ($i = 1; $i -le $Users; $i++) {
        $id++; $fn = $script:PimDemoFirstNames[$rnd.Next($script:PimDemoFirstNames.Count)]; $sn = $script:PimDemoSurnames[$rnd.Next($script:PimDemoSurnames.Count)]
        $principals.Add([pscustomobject]@{ Id = $id; Kind = 'user'; DisplayName = "$fn $sn"; Upn = ('adm-{0}.{1}{2:D4}@contoso.example' -f $fn.ToLowerInvariant(), $sn.ToLowerInvariant(), $i); Department = $script:PimDemoDepartments[$rnd.Next($script:PimDemoDepartments.Count)]; Tier = $rnd.Next(0, 3) })
    }
    $firstGroup = $id + 1
    for ($i = 1; $i -le $Groups; $i++) {
        $id++; $dep = $script:PimDemoDepartments[$rnd.Next($script:PimDemoDepartments.Count)]
        $principals.Add([pscustomobject]@{ Id = $id; Kind = 'group'; DisplayName = ('PIM-L{0}-{1}-{2:D3}' -f $rnd.Next(0, 6), ($dep -replace '\s', ''), $i); Upn = $null; Department = $dep; Tier = $rnd.Next(0, 3) })
    }
    $firstRole = $id + 1
    for ($i = 1; $i -le $Roles; $i++) {
        $id++; $rn = $script:PimDemoRoleNames[($i - 1) % $script:PimDemoRoleNames.Count]
        $principals.Add([pscustomobject]@{ Id = $id; Kind = 'role'; DisplayName = $(if ($i -le $script:PimDemoRoleNames.Count) { $rn } else { "$rn (scope $i)" }); Upn = $null; Department = $null; Tier = $rnd.Next(0, 3) })
    }
    $lastRole = $id
    $assign = New-Object System.Collections.Generic.List[object]
    $aid = 0
    for ($u = 1; $u -le $Users; $u++) {
        $n = 1 + $rnd.Next(0, 4)
        for ($k = 0; $k -lt $n; $k++) {
            $aid++
            $type = if ($rnd.NextDouble() -lt 0.97) { 'Eligible' } else { 'Active' }
            $assign.Add([pscustomobject]@{ Id = $aid; PrincipalId = $u; TargetId = $rnd.Next($firstGroup, $lastRole + 1); AssignmentType = $type; FirstSeenUtc = (& $iso $start.AddMinutes($rnd.NextDouble() * $span * 0.6)) })
        }
    }
    $act = New-Object System.Collections.Generic.List[object]
    $xid = 0
    $days = [int][Math]::Max(1, ($now - $start).TotalDays)
    for ($d = 0; $d -lt $days; $d++) {
        $day = $start.AddDays($d)
        $weekday = ($day.DayOfWeek -ne [DayOfWeek]::Saturday -and $day.DayOfWeek -ne [DayOfWeek]::Sunday)
        $nAct = if ($weekday) { 140 + $rnd.Next(0, 80) } else { 15 + $rnd.Next(0, 20) }
        for ($k = 0; $k -lt $nAct; $k++) {
            $xid++
            $s = $day.AddHours(7 + $rnd.NextDouble() * 11)
            $e = $s.AddMinutes(30 + $rnd.Next(0, 8) * 30)
            $act.Add([pscustomobject]@{ Id = $xid; Kind = 'activation'; Ts = (& $iso $s); StartUtc = (& $iso $s); EndUtc = (& $iso $e); PrincipalId = $rnd.Next(1, $Users + 1); TargetId = $rnd.Next($firstGroup, $lastRole + 1) })
        }
        foreach ($spec in @(@('change', $(if ($weekday) { 40 } else { 6 })), @('approval', $(if ($weekday) { 9 } else { 1 })), @('review', $(if ($weekday) { 25 } else { 0 })))) {
            $cnt = [int]$spec[1] + $rnd.Next(0, [Math]::Max(1, [int]([int]$spec[1] / 3)))
            for ($k = 0; $k -lt $cnt; $k++) { $xid++; $act.Add([pscustomobject]@{ Id = $xid; Kind = $spec[0]; Ts = (& $iso $day.AddMinutes($rnd.NextDouble() * 1440)); StartUtc = $null; EndUtc = $null; PrincipalId = $rnd.Next(1, $Users + 1); TargetId = $rnd.Next($firstGroup, $lastRole + 1) }) }
        }
        if ($rnd.NextDouble() -lt 0.18) { $xid++; $act.Add([pscustomobject]@{ Id = $xid; Kind = 'guard'; Ts = (& $iso $day.AddHours(3)); StartUtc = $null; EndUtc = $null; PrincipalId = $null; TargetId = $null }) }
    }
    $ten = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -le $Tenants; $i++) { $ten.Add([pscustomobject]@{ Id = $i; DisplayName = ('{0} {1}' -f $script:PimDemoSurnames[($i - 1) % $script:PimDemoSurnames.Count], $(if ($i -le $script:PimDemoSurnames.Count) { 'Ltd' } else { "Region $i" })) }) }
    return [pscustomobject]@{ seed = $Seed; generatedUtc = (& $iso $now); principals = @($principals.ToArray()); assignments = @($assign.ToArray()); activity = @($act.ToArray()); tenants = @($ten.ToArray())
        counts = [ordered]@{ users = $Users; groups = $Groups; roles = $Roles; assignments = $assign.Count; activity = $act.Count; tenants = $Tenants } }
}

function ConvertTo-PimDemoRingNumber {
    <# PURE. '1' / 'ring1' / ' Ring 1 ' -> 1; anything else -> $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ("$Value" -match '^\s*(?i:ring)?\s*([0-3])\s*$') { return [int]$Matches[1] }
    return $null
}

function Get-PimDemoModeEligibility {
    <#
      PURE. May THIS environment hold the demo dataset? Positive proof required -- anything unsure is a refusal:
        * the update ring must be RECORDED and be 0 or 1 (2 / 3 = customer rings; not recorded or unreadable = unsure);
        * a licence must be stored, verify (Valid or Grace), and name an internal / demo licensee (customer matching
          -AllowedCustomerPattern, default \b(internal|demo)\b). No licence, an invalid one, or a customer's = refused.
      Returns @{ allowed; reasons[]; ring; customer }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Ring, [bool]$RingRecorded = $false, [AllowEmptyString()][string]$RingError = '',
          [AllowEmptyString()][string]$LicenceStatus = '', [AllowEmptyString()][string]$LicenceCustomer = '', [AllowEmptyString()][string]$LicenceError = '',
          [string]$AllowedCustomerPattern = $script:PimDemoAllowedCustomerPattern)
    $why = New-Object System.Collections.Generic.List[string]
    $rn = ConvertTo-PimDemoRingNumber $Ring
    if ("$RingError".Trim()) { $why.Add("the update ring could not be read ($("$RingError".Trim())) -- unsure, so refused") }
    elseif (-not $RingRecorded -or $null -eq $rn) { $why.Add('the update ring is not recorded in this environment -- unsure, so refused') }
    elseif ($rn -ge 2) { $why.Add("this environment is on update ring $rn (a customer ring) -- demo data is never put on a customer environment") }
    if ("$LicenceError".Trim()) { $why.Add("the licence could not be read ($("$LicenceError".Trim())) -- unsure, so refused") }
    elseif ("$LicenceStatus".Trim() -notin @('Valid', 'Grace')) { $why.Add("no valid licence (status '$("$LicenceStatus".Trim())') -- only the internal / demo licence proves a demo environment") }
    elseif (-not ("$LicenceCustomer" -match $AllowedCustomerPattern)) { $why.Add("the licence is for '$("$LicenceCustomer".Trim())', not an internal / demo licensee -- a customer environment") }
    return [pscustomobject]@{ allowed = ($why.Count -eq 0); reasons = @($why.ToArray()); ring = $rn; customer = "$LicenceCustomer".Trim() }
}

function Test-PimDemoDataActive {
    <# PURE. Is the demo dataset SHOWN? Only with the SQL flag; PIM_DEMO_MODE=off/false/0/no turns it off; PIM_DEMO_MODE=on alone does nothing. #>
    param([AllowNull()][object]$Flag, [AllowNull()][AllowEmptyString()][string]$EnvValue = "$env:PIM_DEMO_MODE")
    $f = "$Flag".Trim() -match '^(?i)(true|1|on|yes)$'
    if (-not $f) { return $false }
    if ("$EnvValue".Trim() -match '^(?i)(false|0|off|no|disabled)$') { return $false }
    return $true
}

function Read-PimDemoFlag {
    <# The flag pimdemo.Meta DemoEnvironment ('' when the schema does not exist -- the normal case). Never throws. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Invoker = $null)
    try {
        $v = Invoke-PimDemoSql -Kind scalar -ConnectionString $ConnectionString -Invoker $Invoker -Sql "IF OBJECT_ID('pimdemo.Meta') IS NULL SELECT CAST(NULL AS NVARCHAR(400)) ELSE SELECT Value FROM pimdemo.Meta WHERE Name = 'DemoEnvironment'"
        if ($null -eq $v -or $v -is [System.DBNull]) { return '' }
        return "$v"
    } catch { return '' }
}

function Get-PimDemoImpactQueries {
    <# PURE. The impact counter queries (Get-PimImpactCounterQueries names) over the demo tables. #>
@{
        activations      = "SELECT COUNT_BIG(*) AS n FROM pimdemo.Activity WHERE Kind = 'activation'"
        activationsSince = "SELECT MIN(Ts) AS n FROM pimdemo.Activity"
        eligible         = "SELECT COUNT_BIG(*) AS n FROM pimdemo.Assignments WHERE AssignmentType = 'Eligible'"
        eligibleMinutes  = "SELECT SUM(CAST(DATEDIFF(minute, FirstSeenUtc, SYSUTCDATETIME()) AS BIGINT)) AS n FROM pimdemo.Assignments WHERE AssignmentType = 'Eligible'"
        activeMinutes    = "SELECT SUM(CAST(DATEDIFF(minute, StartUtc, CASE WHEN EndUtc < SYSUTCDATETIME() THEN EndUtc ELSE SYSUTCDATETIME() END) AS BIGINT)) AS n FROM pimdemo.Activity WHERE Kind = 'activation' AND StartUtc < SYSUTCDATETIME()"
        engineChanges    = "SELECT COUNT_BIG(*) AS n FROM pimdemo.Activity WHERE Kind = 'change'"
        approvals        = "SELECT COUNT_BIG(*) AS n FROM pimdemo.Activity WHERE Kind = 'approval'"
        reviews          = "SELECT COUNT_BIG(*) AS n FROM pimdemo.Activity WHERE Kind = 'review'"
        guardHolds       = "SELECT CONCAT('{""demo"":{""tripCount"":', COUNT_BIG(*), '}}') AS n FROM pimdemo.Activity WHERE Kind = 'guard'"
        since            = "SELECT MIN(Ts) AS n FROM pimdemo.Activity"
        tenants          = 'SELECT COUNT_BIG(*) AS n FROM pimdemo.Tenants'
    }
}

function Get-PimDemoHomeSummary {
    <# The demo principals for the Dashboard's tier tile: { admins; groups; byLevel }. Scoped read. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Invoker = $null)
    $rows = @(Invoke-PimDemoSql -Kind query -ConnectionString $ConnectionString -Invoker $Invoker -Sql "SELECT Kind, LEFT(DisplayName, 6) AS P, COUNT_BIG(*) AS n FROM pimdemo.Principals GROUP BY Kind, LEFT(DisplayName, 6)")
    $admins = 0; $groups = 0; $by = [ordered]@{ L0 = 0; L1 = 0; L2 = 0; L3 = 0; L4 = 0; L5 = 0; untiered = 0 }
    foreach ($r in $rows) {
        if ("$($r.Kind)" -eq 'user') { $admins += [int]$r.n }
        elseif ("$($r.Kind)" -eq 'group') { $groups += [int]$r.n; if ("$($r.P)" -match '^PIM-L([0-5])') { $by["L$($Matches[1])"] += [int]$r.n } else { $by.untiered += [int]$r.n } }
    }
    return [pscustomobject]@{ admins = $admins; groups = $groups; byLevel = $by }
}

function Get-PimDemoHomeTiles {
    <# PURE. The Dashboard tiles in demo mode: every health check green, the tier tile from the demo principals. #>
    param([Parameter(Mandatory)][object]$Summary, [datetime]$NowUtc = [datetime]::UtcNow)
    $t = $NowUtc.ToUniversalTime()
    $iso = { param([datetime]$d) $d.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [ordered]@{
        health           = [ordered]@{ ok = $true; notices = @() }
        jobs             = [ordered]@{ ok = $true; status = 'green'; failedCount = 0; heldCount = 0; skippedCount = 0; runningCount = 0; historyCount = 240
                                       lastRun = [ordered]@{ name = 'engine-delta'; ok = $true; status = 'ok'; whenUtc = (& $iso $t.AddMinutes(-7)) }
                                       nextRun = [ordered]@{ name = 'engine-delta'; whenUtc = (& $iso $t.AddMinutes(8)) }
                                       drift = [ordered]@{ ok = $true; drifted = $false; knownOk = $true; job = 'engine-full' } }
        validation       = [ordered]@{ ok = $true; errors = 0; warnings = 0; ranAtUtc = (& $iso $t.AddMinutes(-3)) }
        breakGlass       = [ordered]@{ active = $false }
        breakGlassChange = [ordered]@{ open = $false }
        approvals        = [ordered]@{ ok = $true; pending = 0; offboards = 0; revokes = 0 }
        tiers            = [ordered]@{ ok = $true; totalGroups = [int]$Summary.groups; admins = [int]$Summary.admins; byLevel = $Summary.byLevel }
        gaps             = [ordered]@{ ok = $true; orphanGroups = 0; gapAdmins = 0; unmanagedTargets = 0 }
        unmanagedAdmins  = [ordered]@{ ok = $true; reported = $true; count = 0; accounts = @(); observedUtc = (& $iso $t.AddHours(-1)) }
    }
}

function ConvertTo-PimDemoInsertSql {
    <# PURE. The INSERT ... SELECT FROM OPENJSON(@j) statement for one demo table. #>
    param([Parameter(Mandatory)][ValidateSet('Principals', 'Assignments', 'Activity', 'Tenants')][string]$Table)
    switch ($Table) {
        'Principals'  { "INSERT INTO pimdemo.Principals (Id, Kind, DisplayName, Upn, Department, Tier) SELECT Id, Kind, DisplayName, Upn, Department, Tier FROM OPENJSON(@j) WITH (Id INT, Kind NVARCHAR(20), DisplayName NVARCHAR(200), Upn NVARCHAR(200), Department NVARCHAR(60), Tier INT);" }
        'Assignments' { "INSERT INTO pimdemo.Assignments (Id, PrincipalId, TargetId, AssignmentType, FirstSeenUtc) SELECT Id, PrincipalId, TargetId, AssignmentType, FirstSeenUtc FROM OPENJSON(@j) WITH (Id INT, PrincipalId INT, TargetId INT, AssignmentType NVARCHAR(20), FirstSeenUtc DATETIME2);" }
        'Activity'    { "INSERT INTO pimdemo.Activity (Id, Kind, Ts, StartUtc, EndUtc, PrincipalId, TargetId) SELECT Id, Kind, Ts, StartUtc, EndUtc, PrincipalId, TargetId FROM OPENJSON(@j) WITH (Id INT, Kind NVARCHAR(30), Ts DATETIME2, StartUtc DATETIME2, EndUtc DATETIME2, PrincipalId INT, TargetId INT);" }
        'Tenants'     { "INSERT INTO pimdemo.Tenants (Id, DisplayName) SELECT Id, DisplayName FROM OPENJSON(@j) WITH (Id INT, DisplayName NVARCHAR(200));" }
    }
}

function Invoke-PimDemoModeChange {
    <#
      The plan + (with -Apply) the change. -Enable: eligibility (refused = throw, nothing written) -> schema -> clear old
      demo rows -> seed (2000 rows per statement) -> flag. -Disable: drop everything (allowed anywhere: removing demo data
      is always safe). -Eligibility: the caller's Get-PimDemoModeEligibility result. -Invoker: test seam for every SQL call.
      Returns @{ action; applied; plan[]; counts }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Enable', 'Disable')][string]$Action, [string]$ConnectionString = 'test', [object]$Eligibility = $null,
          [switch]$Apply, [object]$Dataset = $null, [scriptblock]$Invoker = $null, [int]$ChunkSize = 2000)
    $plan = New-Object System.Collections.Generic.List[string]
    if ($Action -eq 'Disable') {
        $plan.Add('drop every pimdemo table and the pimdemo schema (the demo data is removed completely; the environment''s own data is not touched)')
        if ($Apply) { [void](Invoke-PimDemoSql -Kind nonquery -ConnectionString $ConnectionString -Sql (Get-PimDemoRemoveSql) -Invoker $Invoker) }
        return [pscustomobject]@{ action = 'Disable'; applied = [bool]$Apply; plan = @($plan.ToArray()); counts = $null }
    }
    if ($null -eq $Eligibility -or -not $Eligibility.allowed) {
        $r = if ($Eligibility) { @($Eligibility.reasons) -join '; ' } else { 'the environment was not checked' }
        throw "REFUSED: demo data is allowed only on the internal demo environment -- $r. Nothing was written."
    }
    if (-not $Dataset) { $Dataset = New-PimDemoDataset }
    $plan.Add('create schema pimdemo + its tables (separate from every table the engine reads)')
    $plan.Add('replace any earlier demo rows')
    $plan.Add(("seed {0} users, {1} groups, {2} roles, {3} assignments, {4} activity rows over months, {5} managed tenants" -f $Dataset.counts.users, $Dataset.counts.groups, $Dataset.counts.roles, $Dataset.counts.assignments, $Dataset.counts.activity, $Dataset.counts.tenants))
    $plan.Add('set pimdemo.Meta DemoEnvironment = true (the Dashboard then shows the demo dataset, marked "Demo data")')
    if ($Apply) {
        [void](Invoke-PimDemoSql -Kind nonquery -ConnectionString $ConnectionString -Sql (Get-PimDemoSchemaDdl) -Invoker $Invoker)
        [void](Invoke-PimDemoSql -Kind nonquery -ConnectionString $ConnectionString -Invoker $Invoker -Sql 'DELETE FROM pimdemo.Activity; DELETE FROM pimdemo.Assignments; DELETE FROM pimdemo.Principals; DELETE FROM pimdemo.Tenants; DELETE FROM pimdemo.Meta;')
        foreach ($tbl in @(@('Principals', $Dataset.principals), @('Assignments', $Dataset.assignments), @('Activity', $Dataset.activity), @('Tenants', $Dataset.tenants))) {
            $rows = @($tbl[1]); $sql = ConvertTo-PimDemoInsertSql -Table $tbl[0]
            for ($i = 0; $i -lt $rows.Count; $i += $ChunkSize) {
                $chunk = @($rows[$i..([Math]::Min($i + $ChunkSize - 1, $rows.Count - 1))])
                [void](Invoke-PimDemoSql -Kind nonquery -ConnectionString $ConnectionString -Sql $sql -Parameters @{ j = (ConvertTo-Json -InputObject $chunk -Compress -Depth 3) } -Invoker $Invoker)
            }
        }
        [void](Invoke-PimDemoSql -Kind nonquery -ConnectionString $ConnectionString -Invoker $Invoker -Sql "INSERT INTO pimdemo.Meta (Name, Value) VALUES ('DemoEnvironment', 'true'), ('SeededUtc', @s), ('Seed', @seed);" -Parameters @{ s = "$($Dataset.generatedUtc)"; seed = "$($Dataset.seed)" })
    }
    return [pscustomobject]@{ action = 'Enable'; applied = [bool]$Apply; plan = @($plan.ToArray()); counts = $Dataset.counts }
}
