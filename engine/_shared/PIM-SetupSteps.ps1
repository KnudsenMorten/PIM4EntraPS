#Requires -Version 5.1
<#
.SYNOPSIS
    REQUIREMENTS FLEET-SETUPSTEPS (framework contract, agreed with Invardia 2026-11-03; the same field from SI, PIM and EPS):
    the heartbeat field `setupSteps` -- one entry per ONE-TIME install step, with its state from a REAL check.

.DESCRIPTION
    Shape (Invardia ignores unknown keys; at most 50 entries):
        setupSteps: [ { key; title; state = ok | missing | n/a | unknown; since; how = updater | support-app | customer;
                        checkedAt = <ISO UTC>; detail = <= 200 chars, no secrets } ]
    RULES
      * one entry per one-time step (the step list below is THE list -- install-steps S1-S16);
      * the state comes from a REAL check: the updater reads its facts on every run (Get-PimSetupStepUpdaterFacts) and
        stores them in pim.Settings 'UpdateState'.setupFacts; the heartbeat adds what it reads itself (the setup Controls,
        supportSqlAccess). A fact that could not be read is 'unknown' -- NEVER a guessed ok;
      * `how` = who can fix it.
    WHERE THE FACTS COME FROM
      updater (UpdateState.setupFacts)  private network (the Container Apps environment's internal flag), the Jobs Operator role
                                        + SchedulerTickJobId (converge-defaults lines), CR8 (ACR admin user, Key Vault purge
                                        protection, no SAS in PIM_UPDATE_SOURCE_URL, SQL auditing), the front state (Key Vault
                                        key 'signin-front' + SQL schema 'signin'), the front's private Key Vault, the pull /
                                        publish jobs' Reader on themselves, the as-built storage + rights, the database
                                        job (OPEN-06: present, on version, its identity in the SQL admin group), the
                                        identity names (NAM-03: every role runs as id-pim-<role>, no old identity holds rights)
      updater (UpdateState, own keys)   sqlAccess (run 1 / run 2 / updater in the admin group), signIn (the layer),
                                        enginePermissions (the 95.2i check: Graph + the Reader at the tenant root)
      heartbeat                         Controls (mail-sender, licence-valid, uplink-key, update-ring, identity-permissions),
                                        supportSqlAccess { group; dbUser }, PermissionSnapshot (the Manager's check, or the
                                        engine's own refresh when it is older than 24 h -- SETUPSTEPS-TRUTH (b))
      both (SETUPSTEPS-TRUTH (a))       the read-only SIGNED procedure [pim].[usp_AccessFacts] (Read-PimAccessFacts below): the
                                        Support app's database user + run 2, seen with EXECUTE only (absent = today's read)
    PURE first (New-PimSetupSteps and every mapper -- offline-tested in tests/Test-PimSetupSteps.ps1), then the one reader
    the updater calls (Get-PimSetupStepUpdaterFacts; ARM GET + one SQL scalar through seams; never throws, never writes).
    PS 5.1 + 7, no modules, no az, ASCII only.
#>
Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------------------------------
# THE STEP LIST (install-steps S1-S16). Literal-returning function: child-scope safe ($script: defaults are $null there).
# since = the release that first needs the step; how = who can fix it.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSetupStepCatalog {
    return @(
        [ordered]@{ key = 'mail-sender';              title = 'Mail sender set up';                                  since = '2.4.0';   how = 'customer' }
        [ordered]@{ key = 'private-network';          title = 'Private network (opt-in)';                            since = '3.0.19';  how = 'support-app' }
        [ordered]@{ key = 'support-arm';              title = 'Support app: subscription rights';                    since = '2.4.649'; how = 'customer' }
        [ordered]@{ key = 'support-sql';              title = 'Support app: database access';                        since = '2.4.649'; how = 'support-app' }
        [ordered]@{ key = 'asbuilt-storage';          title = 'As-built storage, identity and job';                  since = '2.4.581'; how = 'updater' }
        [ordered]@{ key = 'asbuilt-rights';           title = 'As-built write right and support role';               since = '2.4.581'; how = 'customer' }
        [ordered]@{ key = 'signin-front';             title = 'Sign-in front in place of Easy Auth';                 since = '2.4.655'; how = 'support-app' }
        [ordered]@{ key = 'front-state';              title = 'Sign-in front key and database schema';               since = '2.4.656'; how = 'support-app' }
        [ordered]@{ key = 'cr8-hardening';            title = 'Registry, Key Vault, update source and SQL audit hardening'; since = '2.4.632'; how = 'support-app' }
        [ordered]@{ key = 'sql-least-privilege';      title = 'Database least privilege (run 1 and run 2)';         since = '2.4.644'; how = 'support-app' }
        [ordered]@{ key = 'updater-not-sql-admin';    title = 'Updater out of the SQL admin group';                  since = '2.4.645'; how = 'support-app' }
        [ordered]@{ key = 'engine-graph-permissions'; title = 'Engine Microsoft Graph permissions';                  since = '2.4.0';   how = 'customer' }
        [ordered]@{ key = 'jobs-operator';            title = 'Manager may start the engine after a change';         since = '2.4.547'; how = 'support-app' }
        [ordered]@{ key = 'licence';                  title = 'Licence and install key';                             since = '2.4.500'; how = 'support-app' }
        [ordered]@{ key = 'update-ring';              title = 'Update ring set';                                     since = '2.4.323'; how = 'support-app' }
        [ordered]@{ key = 'engine-root-reader';       title = 'Engine Reader at the tenant root';                    since = '2.4.529'; how = 'customer' }
        [ordered]@{ key = 'front-private-kv';         title = 'Private Key Vault for the sign-in front';             since = '2.4.656'; how = 'support-app' }
        # SETUPSTEPS-TRUTH (e): the updater may NOT assign roles (P9) -- it only notes the refusal; the Support app grants it
        # (ops grant-job-self-reader.ps1).
        [ordered]@{ key = 'job-self-reader';          title = 'Pull / publish jobs read their own runs';             since = '2.4.636'; how = 'support-app' }
        # OPEN-06 / NO-PERSON-DB-ADMIN: the in-network database job, its version and its identity in the SQL admin group (the
        # updater creates the job; the Support app adds the identity to the group -- the updater never writes a membership).
        [ordered]@{ key = 'db-job';                   title = 'Database job (no person needs database admin)';       since = '3.0.36';  how = 'support-app' }
        # NAM-03 / framework 12.11c item 3 + ruling (b) (key agreed by Invardia 2026-11-07): every role runs as id-pim-<role> and
        # no old identity still holds rights (the updater reads the apps / jobs / identities and the old ones' rights:
        # Read-PimIdentityNamesFact, PIM-IdentitySplit.ps1; the Support app moves an identity -- Move-PimIdentities.ps1).
        [ordered]@{ key = 'identity-names';           title = 'Identity names follow the standard (id-pim-<role>)';  since = '3.0.57';  how = 'support-app' }
    )
}
function Get-PimSetupStepMax { return 50 }
function Get-PimSetupStepDetailMax { return 200 }
function Get-PimSetupStepStateList { return @('ok', 'missing', 'n/a', 'unknown', 'waiting-customer') }
function Test-PimSetupStepTicketId { <# PURE. A customer ticket id SUP-yyyy-nnnnn (framework WAITING-CUSTOMER, 2026-11-08). #> param([AllowNull()][string]$Id) return [bool]("$Id" -cmatch '^SUP-\d{4}-\d{5}$') }
function Get-PimSetupStepHowList { return @('updater', 'support-app', 'customer') }
function Get-PimSetupStepFreshDays { return 7 }

# ---------------------------------------------------------------------------------------------------------------------
# PURE helpers
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSetupStepField {
    # PURE. A property of a PSCustomObject or a dictionary; $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    if ($Object -is [string]) { return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimSetupStepObject {
    # PURE. A stored value as an object: JSON text (also double-encoded) is parsed; unparsable = $null.
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        $s = "$v".Trim(); if (-not $s) { return $null }
        try { $v = $s | ConvertFrom-Json } catch { return $null }
    }
    return $v
}

function ConvertTo-PimSetupStepUtc {
    # PURE. A time (text / [datetime] / [datetimeoffset]) -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    try { return ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } catch { return $null }
}

function ConvertTo-PimSetupStepBool {
    # PURE. $true / $false / 'true' / 'false' / 1 / 0 -> [bool]; anything else (incl. $null) -> $null (= not known).
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = "$Value".Trim().ToLowerInvariant()
    if ($s -in @('true', '1', 'yes')) { return $true }
    if ($s -in @('false', '0', 'no')) { return $false }
    return $null
}

function Test-PimSetupStepSecretText {
    # PURE. Does the text look like it carries a secret? (SAS, account key, password, bearer / JWT, a private key, an install key.)
    param([AllowNull()][string]$Text)
    $t = "$Text"
    if (-not $t) { return $false }
    return [bool]($t -match '(?i)(\bsig=|\bsv=\d|SharedAccessSignature|AccountKey=|password\s*[=:]|pwd\s*=|client_secret|secret\s*[=:]|\bBearer\s+[A-Za-z0-9._-]{8,}|\beyJ[A-Za-z0-9_-]{10,}|-----BEGIN|\binv-[A-Za-z0-9_-]{20,})')
}

function ConvertTo-PimSetupStepDetail {
    # PURE. The detail as it may leave: one line, no secret (a secret-looking text is replaced), at most 200 characters.
    param([AllowNull()][string]$Text)
    $t = ("$Text" -replace '[\r\n\t]+', ' ' -replace '\s{2,}', ' ').Trim()
    if (Test-PimSetupStepSecretText -Text $t) { $t = 'detail withheld (it looked like it carried a secret)' }
    $max = Get-PimSetupStepDetailMax
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }
    return $t
}

function Test-PimSetupStepEntry {
    # PURE. Is one entry valid in the agreed shape? (kebab key, known state / how, a version since, ISO checkedAt, a safe detail)
    param([AllowNull()][object]$Entry)
    if ($null -eq $Entry) { return $false }
    $k = "$(Get-PimSetupStepField $Entry 'key')"
    if ($k -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $k.Length -gt 60) { return $false }
    if ("$(Get-PimSetupStepField $Entry 'state')" -cnotin (Get-PimSetupStepStateList)) { return $false }
    # 'waiting-customer' carries its ticket (SUP-yyyy-nnnnn); a ticket on any other state is not the agreed shape
    $tk = Get-PimSetupStepField $Entry 'ticket'
    if ("$(Get-PimSetupStepField $Entry 'state')" -ceq 'waiting-customer') { if (-not (Test-PimSetupStepTicketId -Id "$tk")) { return $false } }
    elseif ($null -ne $tk) { return $false }
    if ("$(Get-PimSetupStepField $Entry 'how')" -cnotin (Get-PimSetupStepHowList)) { return $false }
    if ("$(Get-PimSetupStepField $Entry 'since')" -notmatch '^\d{1,4}\.\d{1,6}\.\d{1,6}$') { return $false }
    if ("$(Get-PimSetupStepField $Entry 'checkedAt')" -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { return $false }
    $t = "$(Get-PimSetupStepField $Entry 'title')"; if (-not $t.Trim() -or $t.Length -gt 100) { return $false }
    $d = "$(Get-PimSetupStepField $Entry 'detail')"
    if ($d.Length -gt (Get-PimSetupStepDetailMax) -or (Test-PimSetupStepSecretText -Text $d)) { return $false }
    return $true
}

function Get-PimSetupStepControl {
    # PURE. The state of one setup Control (Get-PimSetupControlStates output) by id; $null when absent.
    param([object[]]$Controls = @(), [string]$Id)
    foreach ($c in @($Controls | Where-Object { $null -ne $_ })) { if ("$(Get-PimSetupStepField $c 'id')" -eq $Id) { return $c } }
    return $null
}

function Test-PimUpdateSourceUrlNoSas {
    # PURE. CR8 step 5: PIM_UPDATE_SOURCE_URL carries no SAS (no query string with sig= / sv= / se=). Empty = no SAS ($true).
    param([AllowNull()][string]$Url)
    $u = "$Url".Trim()
    if (-not $u) { return $true }
    $q = ''; $i = $u.IndexOf('?'); if ($i -ge 0) { $q = $u.Substring($i + 1) }
    return -not [bool]($q -match '(?i)(^|&)(sig|sv|se|sp|st|skoid)=')
}

function ConvertFrom-PimSetupConvergeLines {
    <#
      PURE. The converge-defaults lines (Invoke-PimUpdateConvergeDefaults .lines: id; level; text) -> the Jobs Operator facts:
        jobsOperator  'manager-tick-operator': '-- present' = $true, 'MISSING' = $false, 'not checked' = $null
        tickJobIdSet  'tick-start': already set / set / kept = $true, 'not set' = $false, 'not checked' = $null
    #>
    param([object[]]$Lines = @())
    $o = [ordered]@{ jobsOperator = $null; tickJobIdSet = $null }
    foreach ($l in @($Lines | Where-Object { $null -ne $_ })) {
        $id = "$(Get-PimSetupStepField $l 'id')"; $tx = "$(Get-PimSetupStepField $l 'text')"; $lv = "$(Get-PimSetupStepField $l 'level')"
        if ($id -eq 'manager-tick-operator') {
            if ($tx -match '-- present') { $o.jobsOperator = $true } elseif ($tx -match 'MISSING') { $o.jobsOperator = $false } else { $o.jobsOperator = $null }
        } elseif ($id -eq 'tick-start') {
            if ($tx -match 'not checked|not converged') { $o.tickJobIdSet = $null }
            elseif ($tx -match 'not set') { $o.tickJobIdSet = $false }
            elseif ($lv -eq 'changed' -or $tx -match 'already set|-- kept|-- set') { $o.tickJobIdSet = $true }
        }
    }
    return $o
}

function ConvertFrom-PimSetupJobSelfIdResult {
    <#
      PURE. The pull / publish jobs' Reader on themselves (Invoke-PimJobSelfIdUpdate: ok; log[]; notes[]) -> ok | missing | n/a | $null.
      No such job at this install = n/a; a refusal note = missing; the jobs could not be listed = $null (unknown).
    #>
    param([AllowNull()][object]$Result)
    if ($null -eq $Result) { return $null }
    $log = @(@(Get-PimSetupStepField $Result 'log') | Where-Object { $_ })
    $notes = @(@(Get-PimSetupStepField $Result 'notes') | Where-Object { $_ })
    if (@($notes | Where-Object { "$_" -match "'Reader' on itself is not assigned|no identity to grant" }).Count) { return 'missing' }
    if (@($log | Where-Object { "$_" -match "'Reader' on itself (ensured|already assigned)" }).Count) { return 'ok' }
    if ("$(Get-PimSetupStepField $Result 'detail')" -match 'could not be listed') { return $null }
    if (-not $log.Count -and -not $notes.Count) { return 'n/a' }
    return $null
}

function ConvertFrom-PimSetupSqlAuditResult {
    # PURE. SQL auditing (Invoke-PimSqlAuditConverge: ok; lines[]) -> $true (on) / $false (refused, still off) / $null (not checked).
    param([AllowNull()][object]$Result)
    if ($null -eq $Result) { return $null }
    $lines = @(@(Get-PimSetupStepField $Result 'lines') | Where-Object { $_ })
    if (@($lines | Where-Object { "$(Get-PimSetupStepField $_ 'text')" -match 'not checked' }).Count) { return $null }
    $ok = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $Result 'ok')
    return $ok
}

function Get-PimSetupStepAsBuiltFacts {
    <#
      The as-built entries. Get-PimAsBuiltSetupState (engine/_shared/PIM-AsBuilt.ps1, PURE; storage = ok|missing|denied|unknown,
      rights = ok|missing|unknown, detail) is called when it exists -- with whatever of -Result / -Converge / -Lines it declares;
      absent (an older build) = both 'unknown', detail 'not checked by this version'. Never throws.
    #>
    param([AllowNull()][object]$AsBuiltResult)
    $cmd = Get-Command Get-PimAsBuiltSetupState -ErrorAction SilentlyContinue
    if (-not $cmd) { return [ordered]@{ asBuiltStorage = 'unknown'; asBuiltRights = 'unknown'; asBuiltDetail = 'not checked by this version' } }
    try {
        $args2 = @{}
        foreach ($n in @('Result', 'Converge', 'ConvergeResult', 'AsBuilt')) { if ($cmd.Parameters.ContainsKey($n)) { $args2[$n] = $AsBuiltResult } }
        if ($cmd.Parameters.ContainsKey('Lines')) { $args2['Lines'] = @(Get-PimSetupStepField $AsBuiltResult 'lines') }
        $r = Get-PimAsBuiltSetupState @args2
        $st = "$(Get-PimSetupStepField $r 'storage')".Trim().ToLowerInvariant()
        $rt = "$(Get-PimSetupStepField $r 'rights')".Trim().ToLowerInvariant()
        if ($st -notin @('ok', 'missing', 'denied', 'unknown')) { $st = 'unknown' }
        if ($rt -notin @('ok', 'missing', 'unknown')) { $rt = 'unknown' }
        return [ordered]@{ asBuiltStorage = $st; asBuiltRights = $rt; asBuiltDetail = "$(Get-PimSetupStepField $r 'detail')" }
    } catch {
        return [ordered]@{ asBuiltStorage = 'unknown'; asBuiltRights = 'unknown'; asBuiltDetail = "the as-built state could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    }
}

function Get-PimSetupStepDbJobFacts {
    <#
      OPEN-06: the 'db-job' facts. Get-PimDbInitSetupState (engine/_shared/PIM-DbInitJob.ps1, PURE; dbJob = ok|missing|unknown,
      dbJobDetail) is called when it exists; absent (a build without it) = 'unknown', detail 'not checked by this version'.
      Never throws.
    #>
    param([AllowNull()][object]$DbInitResult)
    if (-not (Get-Command Get-PimDbInitSetupState -ErrorAction SilentlyContinue)) { return [ordered]@{ dbJob = 'unknown'; dbJobDetail = 'not checked by this version' } }
    try {
        $r = Get-PimDbInitSetupState -Result $DbInitResult
        $st = "$(Get-PimSetupStepField $r 'dbJob')".Trim().ToLowerInvariant()
        if ($st -notin @('ok', 'missing', 'unknown')) { $st = 'unknown' }
        return [ordered]@{ dbJob = $st; dbJobDetail = "$(Get-PimSetupStepField $r 'dbJobDetail')" }
    } catch {
        return [ordered]@{ dbJob = 'unknown'; dbJobDetail = "the database job state could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# SETUPSTEPS-TRUTH (a): THE ACCESS FACTS, read through the read-only SIGNED procedure [pim].[usp_AccessFacts]
# (engine/_shared/PIM-SqlAccess.ps1 Get-PimSqlAccessFactsProcedureText; installed by an admin run). The engine's and the
# updater's least-privilege database users may not see OTHER database users (no VIEW DEFINITION, by design); the procedure
# is signed by a certificate whose user holds VIEW DEFINITION only, so a caller with EXECUTE alone gets the FACTS (counts
# and one SID), never the principals. Absent / unsigned / not answered = $null (unknown) -- the caller keeps today's read.
# Here: the caller's half (PURE text + parser, and one reader that never throws), loaded by the heartbeat AND the updater.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAccessFactsProcedureName { <# PURE. The procedure (a literal; PIM-SqlAccess.ps1 creates it under this name). #> return '[pim].[usp_AccessFacts]' }

function Get-PimAccessFactsCallSql {
    <#
      PURE. The ONE call: EXEC [pim].[usp_AccessFacts] with three COMPARED values (the procedure never executes them):
        -AppIds        the Support app ids Microsoft Graph named (GUIDs only; anything else is dropped)
        -DbUserName    the Support app's database user name (Grant-PimSupportAccess default 'invardia-support')
        -RuntimeUsers  the web app's and the engine's database user names (run 2: do they still hold db_datareader / db_datawriter?)
      A name that is not a safe database user name (no comma, no quote) is dropped, never sent.
    #>
    param([string[]]$AppIds = @(), [string]$DbUserName = 'invardia-support', [string[]]$RuntimeUsers = @())
    $safe = '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$'
    $ids = @(@($AppIds) | ForEach-Object { $g = [guid]::Empty; if ([guid]::TryParse("$_".Trim(), [ref]$g) -and $g -ne [guid]::Empty) { $g.ToString() } } | Select-Object -Unique)
    $rt = @(@($RuntimeUsers) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match $safe } | Select-Object -Unique)
    $du = $(if ("$DbUserName".Trim() -match $safe) { "N'$("$DbUserName".Trim())'" } else { 'NULL' })
    return ("EXEC $(Get-PimAccessFactsProcedureName) @AppIds = N'$($ids -join ',')', @DbUserName = $du, @RuntimeUsers = N'$($rt -join ',')';")
}

function ConvertFrom-PimSetupStepSid {
    # PURE. A SID as SQL returns it from CONVERT(NVARCHAR, sid, 1) ('0x' + 32 hex, Guid.ToByteArray order) -> the app id; else ''.
    param([AllowNull()][string]$Sid)
    if ("$Sid".Trim() -notmatch '^(0x)?([0-9a-fA-F]{32})$') { return '' }
    $hex = $Matches[2]; $b = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    return ([guid]::new([byte[]]$b)).ToString()
}

function ConvertFrom-PimAccessFactsAnswer {
    <#
      PURE. The procedure's ONE scalar 'v1|visible|sidUsers|sidInRole|namedSid|namedInRole|runtimeFound|broadUsers' ->
      @{ visible; sidUsers; sidInRole; namedExists; namedAppId; namedInRole; runtimeFound; broadUsers } (the same keys the
      heartbeat's own read gives, so Resolve-PimUplinkSupportDbUser judges both alike). Anything else THROWS.
    #>
    param([AllowNull()]$Raw)
    if ("$Raw".Trim() -notmatch '^v1\|([01])\|(\d+)\|(\d+)\|((0x)?[0-9A-Fa-f]*)\|(\d+)\|(\d+)\|(\d+)$') { throw 'the access facts procedure did not answer in its agreed form' }
    $sid = "$($Matches[4])"
    return @{ visible = ($Matches[1] -eq '1'); sidUsers = [int]$Matches[2]; sidInRole = [int]$Matches[3]
              namedExists = [bool]$sid; namedAppId = (ConvertFrom-PimSetupStepSid $sid); namedInRole = [int]$Matches[6]
              runtimeFound = [int]$Matches[7]; broadUsers = [int]$Matches[8] }
}

function Test-PimAccessFactsAbsent {
    # PURE. Is this error the procedure missing on this install (no admin run has installed it yet)?
    param([AllowNull()][string]$Message)
    return [bool]("$Message" -match '(?i)Could not find stored procedure|Msg 2812|usp_AccessFacts.{0,40}(not found|does not exist)')
}

function Read-PimAccessFacts {
    <#
      ONE read through the signed procedure. NEVER throws. -Scalar { param($sql) } = one scalar from the PIM database.
      Returns @{ present = $true | $false | $null; facts = <ConvertFrom-PimAccessFactsAnswer> | $null; reason }:
        present $true   it answered; facts.visible says whether its signature let it see the other users (an UNSIGNED --
                        tampered / re-created -- procedure answers visible = 0: the caller treats that as not determined)
        present $false  not installed on this install (today's behaviour: the caller keeps its own read / unknown)
        present $null   it could not be called (no EXECUTE, a timeout, a bad answer) -- unknown
    #>
    param([AllowNull()][scriptblock]$Scalar, [string[]]$AppIds = @(), [string]$DbUserName = 'invardia-support', [string[]]$RuntimeUsers = @())
    if (-not $Scalar) { return @{ present = $null; facts = $null; reason = 'no database session' } }
    try {
        $raw = & $Scalar (Get-PimAccessFactsCallSql -AppIds $AppIds -DbUserName $DbUserName -RuntimeUsers $RuntimeUsers)
        $f = ConvertFrom-PimAccessFactsAnswer $raw
        if (-not $f.visible) { return @{ present = $true; facts = $f; reason = 'the access facts procedure is not signed (it sees only itself) -- not determined' } }
        return @{ present = $true; facts = $f; reason = '' }
    } catch {
        $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim()
        if (Test-PimAccessFactsAbsent $m) { return @{ present = $false; facts = $null; reason = 'the access facts procedure is not installed here (an admin run installs it)' } }
        return @{ present = $null; facts = $null; reason = "the access facts procedure could not be read: $m" }
    }
}

function Get-PimAccessFactsRun2 {
    <#
      PURE. Run 2 (framework 12.23 P8: no runtime user -- web / engine -- holds db_datareader / db_datawriter any more) from a
      Read-PimAccessFacts result: $true / $false, or $null when not determined (absent, unsigned, or none of the named runtime
      users exists -- 0 of 0 is never "done").
    #>
    param([AllowNull()][object]$Read)
    if ($null -eq $Read -or $Read.present -ne $true -or $null -eq $Read.facts -or -not $Read.facts.visible) { return $null }
    if ([int]$Read.facts.runtimeFound -lt 1) { return $null }
    return ([int]$Read.facts.broadUsers -eq 0)
}

# ---------------------------------------------------------------------------------------------------------------------
# THE BUILDER (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function New-PimSetupSteps {
    <#
      PURE. The setupSteps array from the facts. -Facts (dictionary or object, every part optional):
        Updater           UpdateState.setupFacts (Get-PimSetupStepUpdaterFacts) -- incl. checkedUtc
        UpdateState       pim.Settings 'UpdateState' (sqlAccess, signIn, enginePermissions, tsUtc)
        Controls          Get-PimSetupControlStates output (id; state; value)
        SupportSqlAccess  { group; dbUser } (the heartbeat's own read)
        SupportConsent    pim.Settings 'SupportConsentState' (OPEN-01: the updater's last consent decision; consent none -> n/a)
        Permissions       pim.Settings 'PermissionSnapshot' (the Manager's last check)
        NowUtc            the heartbeat's time
      A missing fact = 'unknown' with a detail saying what was not read. Every entry validated (Test-PimSetupStepEntry);
      at most 50. Returns @( [ordered]@{ key; title; state; since; how; checkedAt; detail } ).
    #>
    param([AllowNull()][object]$Facts)
    $now = ConvertTo-PimSetupStepUtc (Get-PimSetupStepField $Facts 'NowUtc'); if (-not $now) { $now = [datetime]::UtcNow }
    $iso = { param($t) $u = ConvertTo-PimSetupStepUtc $t; if (-not $u) { $u = $now }; $u.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $up = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'Updater')
    $us = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'UpdateState')
    $ctl = @(Get-PimSetupStepField $Facts 'Controls')
    $ssa = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'SupportSqlAccess')
    $perm = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'Permissions')
    $upAt = Get-PimSetupStepField $up 'checkedUtc'
    $usAt = Get-PimSetupStepField $us 'tsUtc'
    $noUp = 'not read: no updater run has recorded this check yet'
    $uf = { param($n) if ($null -eq $up) { return $null }; return (Get-PimSetupStepField $up $n) }
    $ub = { param($n) ConvertTo-PimSetupStepBool (& $uf $n) }

    $res = @{}
    $set = { param($key, $state, $detail, $at) $res[$key] = @{ state = $state; detail = "$detail"; at = $at } }

    # ---- S1 mail-sender (heartbeat Control) ------------------------------------------------------------------------
    $c = Get-PimSetupStepControl -Controls $ctl -Id 'mail-sender'
    switch ("$(Get-PimSetupStepField $c 'state')") {
        'ok'      { & $set 'mail-sender' 'ok' 'the mail sender is set up' (Get-PimSetupStepField $c 'checkedUtc') }
        'missing' { & $set 'mail-sender' 'missing' 'no mail sender is set up (Get Started > Mail sender; the customer''s Exchange admin)' (Get-PimSetupStepField $c 'checkedUtc') }
        'wrong'   { & $set 'mail-sender' 'missing' 'the last test mail failed: the mail sender does not work' (Get-PimSetupStepField $c 'checkedUtc') }
        default   { & $set 'mail-sender' 'unknown' 'not read: the mail settings could not be read' $null }
    }

    # ---- S2 private-network (updater: the Container Apps environment's internal flag) --------------------------------
    $pn = & $ub 'privateNetwork'
    if ($null -eq $up) { & $set 'private-network' 'unknown' $noUp $null }
    elseif ($pn -eq $true) { & $set 'private-network' 'ok' 'the Container Apps environment is on an internal virtual network' $upAt }
    elseif ($pn -eq $false) { & $set 'private-network' 'n/a' 'public environment (a private network is opt-in)' $upAt }
    else { & $set 'private-network' 'unknown' 'not read: the Container Apps environment could not be read' $upAt }

    # ---- S3a support-arm (Invardia's own app; PIM has no read of it) -----------------------------------------------
    & $set 'support-arm' 'unknown' 'not checked by PIM: Invardia reads its own Support app''s rights' $null

    # ---- S3b support-sql (heartbeat supportSqlAccess) --------------------------------------------------------------
    if ($null -eq $ssa) { & $set 'support-sql' 'unknown' 'not read: the Support app''s database access was not checked this heartbeat' $null }
    else {
        $g = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $ssa 'group'); $d = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $ssa 'dbUser')
        $at = Get-PimSetupStepField $ssa 'checkedUtc'
        # ALIGN 2026-11-04 (framework "setupSteps on the heartbeat", Invardia commit 45ea65b; SECAUDIT-1a / OPEN-01): ok = the
        # standing READ-ONLY role + the just-in-time grant path (the signed pimsupport procedures) are in place. The SQL admin
        # group / db_owner no longer make this ok -- standing admin access is what SECAUDIT-1a removes. Read, never inferred:
        # readOnly is sent only when the JIT procedures answered; jitOpen false WITHOUT readOnly = the JIT path is not set up.
        $ro = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $ssa 'readOnly'); $jo = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $ssa 'jitOpen')
        $standing = (@($(if ($g -eq $true) { 'SQL admin group' }), $(if ($d -eq $true) { 'db_owner' })) | Where-Object { $_ }) -join ' + '
        # OPEN-01 (framework "SUPPORT ACCESS" point 1): the standing read-only access = the role pim_support_read (SELECT on the
        # product schemas only). Consent none (Invardia's answer, as the UPDATER last applied it -- pim.Settings
        # SupportConsentState) = NO Support database user, as agreed: n/a, never 'missing'.
        $scRec = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'SupportConsent')
        $scLevel = "$(Get-PimSetupStepField $scRec 'consent')".Trim().ToLowerInvariant()
        if ($scLevel -eq 'none' -and $ro -ne $true -and $jo -ne $true) { & $set 'support-sql' 'n/a' 'the customer gave no consent to support database access (none): no Support database user, as agreed' $at }
        elseif ($ro -eq $true) { & $set 'support-sql' 'ok' 'the standing read-only access (pim_support_read) and the just-in-time grant path are in place' $at }
        elseif ($ro -eq $false) { & $set 'support-sql' 'missing' 'the just-in-time grant path is in place, the standing read-only access is missing (role pim_support_read)' $at }
        elseif ($jo -eq $false) { & $set 'support-sql' 'missing' ("the just-in-time grant path is not set up on this install$(if ($standing) { " (standing access meanwhile: $standing)" })") $at }
        else { & $set 'support-sql' 'unknown' 'not determined: the just-in-time access state could not be read' $at }
    }
    # SUPPORT-SQL-JIT-1 (framework rule, owner 2026-11-09): the Support app is SQL admin only through a TIME-LIMITED membership
    # of the SQL admin group made by the updater while a support session is open. A PERMANENT member / owner assignment of the
    # Support app there (read by the updater, pim.Settings SupportConsentState.sqlGroup.permanent) is a FINDING, said first in
    # plain words -- the state stays what the database read says; its removal is a separate recorded step, never this code.
    $sgRec = Get-PimSetupStepField (ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'SupportConsent')) 'sqlGroup'
    $sgPerm = @(@(Get-PimSetupStepField $sgRec 'permanent') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object -Unique)
    # IDENTITY-MOVE-1 13: once the updater's swap is done (sqlGroup.swapDone, no permanent read back) the step says
    # "time-limited (swapped <utc>)" first. Its state stays what the database read says (ok when the read-only user + the
    # just-in-time path are in place) -- the swap never makes a missing database part look done.
    $sgSwap = ConvertTo-PimSetupStepUtc (Get-PimSetupStepField $sgRec 'swapDone')
    if ($sgPerm.Count -and $res.ContainsKey('support-sql')) {
        $sgWarn = "WARNING: the Support app holds a PERMANENT $($sgPerm -join ' + ') assignment on the SQL admin group (SQL admin with no support session open)"
        $res['support-sql'].detail = "$sgWarn; $($res['support-sql'].detail)"
    } elseif ($sgSwap -and $res.ContainsKey('support-sql')) {
        $res['support-sql'].detail = "time-limited (swapped $($sgSwap.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture))); $($res['support-sql'].detail)"
    }

    # ---- S4a / S4b as-built (updater, Get-PimAsBuiltSetupState) ------------------------------------------------------
    if ($null -eq $up) { & $set 'asbuilt-storage' 'unknown' $noUp $null; & $set 'asbuilt-rights' 'unknown' $noUp $null }
    else {
        $abs = "$(& $uf 'asBuiltStorage')".Trim().ToLowerInvariant(); $abr = "$(& $uf 'asBuiltRights')".Trim().ToLowerInvariant()
        $abd = "$(& $uf 'asBuiltDetail')".Trim()
        switch ($abs) {
            'ok'      { & $set 'asbuilt-storage' 'ok' $(if ($abd) { $abd } else { 'the as-built storage, identity and job are in place' }) $upAt }
            'missing' { & $set 'asbuilt-storage' 'missing' $(if ($abd) { $abd } else { 'the as-built storage, identity or job is missing' }) $upAt }
            'denied'  { & $set 'asbuilt-storage' 'missing' $(if ($abd) { $abd } else { 'the as-built storage was refused (a tenant policy)' }) $upAt }
            default   { & $set 'asbuilt-storage' 'unknown' $(if ($abd) { $abd } else { 'not checked by this version' }) $upAt }
        }
        switch ($abr) {
            'ok'      { & $set 'asbuilt-rights' 'ok' 'the as-built job may write its PDF and the support role exists' $upAt }
            'missing' { & $set 'asbuilt-rights' 'missing' $(if ($abd) { $abd } else { 'the as-built write right or the support role is missing (an Owner grants them)' }) $upAt }
            default   { & $set 'asbuilt-rights' 'unknown' $(if ($abd) { $abd } else { 'not checked by this version' }) $upAt }
        }
    }

    # ---- S5 signin-front (UpdateState.signIn) ------------------------------------------------------------------------
    $si = Get-PimSetupStepField $us 'signIn'; $layer = "$(Get-PimSetupStepField $si 'layer')".Trim().ToLowerInvariant()
    switch ($layer) {
        'signin-front' { & $set 'signin-front' 'ok' "the Manager signs in through the sign-in front$(if ("$(Get-PimSetupStepField $si 'version')".Trim() -match '^\d+(\.\d+){1,3}$') { " $("$(Get-PimSetupStepField $si 'version')".Trim())" })" $usAt }
        'easyauth'     { & $set 'signin-front' 'missing' 'the Manager still signs in through Easy Auth (the front move is not done)' $usAt }
        'none'         { & $set 'signin-front' 'missing' 'the Manager has no sign-in layer in front of it' $usAt }
        default        { & $set 'signin-front' 'unknown' 'not read: the updater has not recorded the Manager''s sign-in layer' $usAt }
    }

    # ---- S5b front-state (updater: Key Vault key + SQL schema; only behind the front) ------------------------------
    if ($layer -in @('easyauth', 'none')) { & $set 'front-state' 'n/a' 'the sign-in front is not in use' $usAt }
    elseif ($null -eq $up) { & $set 'front-state' 'unknown' $noUp $null }
    else {
        $fk = & $ub 'frontKey'; $fs = & $ub 'frontSqlSchema'
        if ($fk -eq $true -and $fs -eq $true) { & $set 'front-state' 'ok' 'the front''s Key Vault key and database schema exist' $upAt }
        elseif ($fk -eq $false -or $fs -eq $false) { & $set 'front-state' 'missing' ("missing: " + ((@($(if ($fk -eq $false) { "Key Vault key 'signin-front'" }), $(if ($fs -eq $false) { "database schema 'signin'" })) | Where-Object { $_ }) -join ', ')) $upAt }
        else { & $set 'front-state' 'unknown' 'not read: the front''s Key Vault key or database schema could not be read' $upAt }
    }

    # ---- S6 cr8-hardening (updater) ----------------------------------------------------------------------------------
    if ($null -eq $up) { & $set 'cr8-hardening' 'unknown' $noUp $null }
    else {
        $items = [ordered]@{ 'registry admin user off' = (& $ub 'acrAdminOff'); 'Key Vault purge protection' = (& $ub 'kvPurgeProtection')
                             'update source without SAS' = (& $ub 'sourceUrlNoSas'); 'SQL auditing on' = (& $ub 'sqlAudit') }
        $bad = @($items.Keys | Where-Object { $items[$_] -eq $false }); $unk = @($items.Keys | Where-Object { $null -eq $items[$_] })
        if ($bad.Count) { & $set 'cr8-hardening' 'missing' ("not done: $($bad -join ', ')$(if ($unk.Count) { "; not read: $($unk -join ', ')" })") $upAt }
        elseif ($unk.Count) { & $set 'cr8-hardening' 'unknown' ("not read: $($unk -join ', ')") $upAt }
        else { & $set 'cr8-hardening' 'ok' 'registry admin user off, Key Vault purge protection on, no SAS in the update source, SQL auditing on' $upAt }
    }

    # ---- S7/S8 sql-least-privilege, S9 updater-not-sql-admin (UpdateState.sqlAccess) --------------------------------
    $sa = Get-PimSetupStepField $us 'sqlAccess'; $saAt = Get-PimSetupStepField $sa 'checkedUtc'; if (-not $saAt) { $saAt = $usAt }
    if ($null -eq $sa) { & $set 'sql-least-privilege' 'unknown' 'not read: the updater has not recorded the database access model' $null; & $set 'updater-not-sql-admin' 'unknown' 'not read: the updater has not recorded the database access model' $null }
    else {
        $model = "$(Get-PimSetupStepField $sa 'model')"; $r1 = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $sa 'run1'); $r2 = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $sa 'run2')
        # SQLACCESS-STORED (2026-11-05): run2Source 'stored' = the updater could not read run 2 live (it left the SQL admin group
        # and no readable facts procedure) and carried its STORED cut-over record -- ok, said as stored, with the record's time
        # and why the live read was not possible. No record and no read = unknown WITH the reason (never a bare "could not be read").
        $r2Src = "$(Get-PimSetupStepField $sa 'run2Source')".Trim(); $r2Why = "$(Get-PimSetupStepField $sa 'run2Reason')".Trim()
        $r2At = "$(Get-PimSetupStepField $sa 'run2CheckedUtc')".Trim()
        if ($model -eq 'least-privilege' -and $r1 -eq $true -and $r2 -eq $true) {
            if ($r2Src -eq 'stored') { & $set 'sql-least-privilege' 'ok' ("run 1 and run 2 done (run 2: stored cut-over record$(if ($r2At) { " of $r2At" }); not read live: $(if ($r2Why) { $r2Why } else { 'the live read is not permitted' }))") $saAt }
            else { & $set 'sql-least-privilege' 'ok' 'least privilege: run 1 and run 2 are done' $saAt }
        }
        elseif ($model -eq 'broad' -or $r1 -eq $false -or $r2 -eq $false) { & $set 'sql-least-privilege' 'missing' ("not done: " + ((@($(if ($r1 -ne $true) { 'run 1' }), $(if ($r2 -ne $true) { 'run 2' })) | Where-Object { $_ }) -join ', ')) $saAt }
        elseif ($model -eq 'least-privilege' -and $r1 -eq $true) { & $set 'sql-least-privilege' 'unknown' ("not determined: run 1 done; run 2 not read, no stored cut-over record: $(if ($r2Why) { $r2Why } else { 'the updater did not say why' })") $saAt }
        else { & $set 'sql-least-privilege' 'unknown' 'not determined: the access model could not be read' $saAt }
        $ia = ConvertTo-PimSetupStepBool (Get-PimSetupStepField $sa 'updaterInAdminGroup')
        if ($ia -eq $false) { & $set 'updater-not-sql-admin' 'ok' 'the updater is not in the SQL admin group' $saAt }
        elseif ($ia -eq $true) { & $set 'updater-not-sql-admin' 'missing' 'the updater is still in the SQL admin group' $saAt }
        else { & $set 'updater-not-sql-admin' 'unknown' 'not determined: the SQL admin group could not be read' $saAt }
    }

    # ---- S10 engine-graph-permissions + S14 engine-root-reader (UpdateState.enginePermissions, else the Manager) -------
    $ep = Get-PimSetupStepField $us 'enginePermissions'; $epAt = Get-PimSetupStepField $ep 'checkedUtc'
    $gs = "$(Get-PimSetupStepField $ep 'graphState')"
    $psAt = ConvertTo-PimSetupStepUtc (Get-PimSetupStepField $perm 'checkedUtc')
    $psFresh = ($perm -and $psAt -and ($now - $psAt).TotalDays -le (Get-PimSetupStepFreshDays) -and (ConvertTo-PimSetupStepBool (Get-PimSetupStepField $perm 'readable')) -eq $true)
    $psWho = { if ("$(Get-PimSetupStepField $perm 'source')" -eq 'engine') { "engine's own" } else { "PIM Manager's" } }
    if ($gs -eq 'ok') { & $set 'engine-graph-permissions' 'ok' 'the engine holds every Microsoft Graph permission this version needs' $epAt }
    elseif ($gs -eq 'missing') {
        $mg = @(@(Get-PimSetupStepField $ep 'missingGraph') | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' })
        & $set 'engine-graph-permissions' 'missing' ("missing: $($mg -join ', ')") $epAt
    } else {
        $ic = Get-PimSetupStepControl -Controls $ctl -Id 'identity-permissions'
        switch ("$(Get-PimSetupStepField $ic 'state')") {
            # SETUPSTEPS-TRUTH (b): the snapshot is the PIM Manager's check OR the engine's own daily refresh (source = engine)
            'ok'      { & $set 'engine-graph-permissions' 'ok' "from the $(& $psWho) permission check (7 days or newer)" (Get-PimSetupStepField $ic 'checkedUtc') }
            'missing' { & $set 'engine-graph-permissions' 'missing' "the $(& $psWho) permission check found missing permissions (Home > Permissions)" (Get-PimSetupStepField $ic 'checkedUtc') }
            default   {
                $why = "$(Get-PimSetupStepField $ep 'reason')".Trim()
                & $set 'engine-graph-permissions' 'unknown' $(if ($why) { "not checked: $why" } else { 'not checked: no readable permission check from the last 7 days' }) $epAt
            }
        }
    }
    $as = "$(Get-PimSetupStepField $ep 'azureState')"
    $ma = @(@(Get-PimSetupStepField $ep 'missingAzure') | ForEach-Object { "$_" })
    if ($as -in @('ok', 'missing')) {
        if (@($ma | Where-Object { $_ -match '^Reader at the tenant root' }).Count) { & $set 'engine-root-reader' 'missing' 'the engine has no Reader at the tenant root management group' $epAt }
        else { & $set 'engine-root-reader' 'ok' 'the engine holds Reader at the tenant root management group' $epAt }
    } elseif ($psFresh -and (ConvertTo-PimSetupStepBool (Get-PimSetupStepField $perm 'rootReader')) -is [bool]) {
        # an engine-made snapshot CARRIES rootReader from the last check that read it (the tick reads no ARM): that time counts
        $rrAt = ConvertTo-PimSetupStepUtc (Get-PimSetupStepField $perm 'rootReaderCheckedUtc'); if (-not $rrAt) { $rrAt = $psAt }
        if ([bool](ConvertTo-PimSetupStepBool (Get-PimSetupStepField $perm 'rootReader'))) { & $set 'engine-root-reader' 'ok' 'from the PIM Manager''s permission check' $rrAt }
        else { & $set 'engine-root-reader' 'missing' 'the PIM Manager''s permission check found no Reader at the tenant root' $rrAt }
    } else { & $set 'engine-root-reader' 'unknown' 'not read: the engine''s Azure role assignments could not be read' $epAt }

    # ---- S11 jobs-operator (updater: converge-defaults) ------------------------------------------------------------
    if ($null -eq $up) { & $set 'jobs-operator' 'unknown' $noUp $null }
    else {
        $jo = & $ub 'jobsOperator'; $tj = & $ub 'tickJobIdSet'
        if ($jo -eq $true -and $tj -eq $true) { & $set 'jobs-operator' 'ok' 'the Manager holds Container Apps Jobs Operator on the engine job and SchedulerTickJobId is set' $upAt }
        elseif ($jo -eq $false -or $tj -eq $false) { & $set 'jobs-operator' 'missing' ("missing: " + ((@($(if ($jo -eq $false) { "the Manager's Container Apps Jobs Operator role on the engine job" }), $(if ($tj -eq $false) { 'SchedulerTickJobId' })) | Where-Object { $_ }) -join ', ')) $upAt }
        else { & $set 'jobs-operator' 'unknown' 'not read: the Manager''s role assignments could not be read' $upAt }
    }

    # ---- S12 licence (heartbeat Controls licence-valid + uplink-key) -----------------------------------------------
    $lv = "$(Get-PimSetupStepField (Get-PimSetupStepControl -Controls $ctl -Id 'licence-valid') 'state')"; $uk = "$(Get-PimSetupStepField (Get-PimSetupStepControl -Controls $ctl -Id 'uplink-key') 'state')"
    if ($lv -eq 'ok' -and $uk -eq 'ok') { & $set 'licence' 'ok' 'a valid licence for this tenant and the Invardia install key are in place' $null }
    elseif ($lv -in @('missing', 'wrong') -or $uk -eq 'missing') { & $set 'licence' 'missing' ("not done: " + ((@($(if ($lv -eq 'missing') { 'no licence' } elseif ($lv -eq 'wrong') { 'the licence is expired or for another tenant' }), $(if ($uk -eq 'missing') { 'no install key' })) | Where-Object { $_ }) -join ', ')) $null }
    else { & $set 'licence' 'unknown' 'not read: the licence could not be read' $null }

    # ---- S13 update-ring (heartbeat Control) ---------------------------------------------------------------------
    $rc = Get-PimSetupStepControl -Controls $ctl -Id 'update-ring'
    switch ("$(Get-PimSetupStepField $rc 'state')") {
        'ok'      { & $set 'update-ring' 'ok' $(if ("$(Get-PimSetupStepField $rc 'value')" -match '^[0-3]$') { "ring $(Get-PimSetupStepField $rc 'value')" } else { 'the ring is set' }) (Get-PimSetupStepField $rc 'checkedUtc') }
        'missing' { & $set 'update-ring' 'missing' 'no update ring is set on the updater' (Get-PimSetupStepField $rc 'checkedUtc') }
        default   { & $set 'update-ring' 'unknown' 'not read: the update state could not be read' $null }
    }

    # ---- S15 front-private-kv (updater: the vaults in the resource group) --------------------------------------------
    if ($null -eq $up) { & $set 'front-private-kv' 'unknown' $noUp $null }
    else {
        switch ("$(& $uf 'frontKvPrivate')") {
            'private'            { & $set 'front-private-kv' 'ok' 'the Key Vault is private and reached through a private endpoint' $upAt }
            'private-no-endpoint'{ & $set 'front-private-kv' 'missing' 'the Key Vault denies public access but has no private endpoint' $upAt }
            'public'             { & $set 'front-private-kv' 'n/a' 'the Key Vault allows public access (a private vault is needed only where a policy denies it)' $upAt }
            'none'               { & $set 'front-private-kv' 'n/a' 'no Key Vault in the resource group' $upAt }
            default              { & $set 'front-private-kv' 'unknown' 'not read: the Key Vaults could not be read' $upAt }
        }
    }

    # ---- S16 job-self-reader (updater: Invoke-PimJobSelfIdUpdate) ---------------------------------------------------
    if ($null -eq $up) { & $set 'job-self-reader' 'unknown' $noUp $null }
    else {
        switch ("$(& $uf 'jobSelfReader')") {
            'ok'      { & $set 'job-self-reader' 'ok' 'every pull / publish job holds Reader on itself' $upAt }
            'missing' { & $set 'job-self-reader' 'missing' 'a pull / publish job has no Reader on itself (the updater may not assign roles -- the Support app grants it)' $upAt }
            'n/a'     { & $set 'job-self-reader' 'n/a' 'no pull or publish job at this install' $upAt }
            default   { & $set 'job-self-reader' 'unknown' 'not read: the jobs could not be listed' $upAt }
        }
    }

    # ---- S17 db-job (updater: Invoke-PimDbInitJobConverge -> Get-PimDbInitSetupState) --------------------------------
    # A state is READ, never inferred: ok only when the updater read the job present, on the Manager's version AND its
    # identity in the SQL admin group (dbJob = 'ok'); anything else it read is missing (with WHICH); not read = unknown.
    if ($null -eq $up) { & $set 'db-job' 'unknown' $noUp $null }
    else {
        $dj = "$(& $uf 'dbJob')".Trim().ToLowerInvariant(); $djd = "$(& $uf 'dbJobDetail')".Trim()
        switch ($dj) {
            'ok'      { & $set 'db-job' 'ok' $(if ($djd) { $djd } else { 'the database job is in place, on this version, its identity in the SQL admin group' }) $upAt }
            'missing' { & $set 'db-job' 'missing' $(if ($djd) { $djd } else { 'the database job, its version or its identity in the SQL admin group is missing' }) $upAt }
            default   { & $set 'db-job' 'unknown' $(if ($djd) { "not determined: $djd" } else { 'not checked by this version' }) $upAt }
        }
    }

    # ---- S18 identity-names (updater: Read-PimIdentityNamesFact, PIM-IdentitySplit.ps1) --------------------------------
    # Framework 12.11c ruling (b), 2026-11-07: ok only when the updater READ every role running as id-pim-<role> AND no old
    # identity (shared id-pim-<token>, a named variant, a system-assigned one) still holding a right; otherwise missing (the
    # detail names them: "app: identity", "clean-up pending: <identity> still holds rights"); nothing to read = n/a; nothing
    # decided / an older updater = unknown.
    if ($null -eq $up) { & $set 'identity-names' 'unknown' $noUp $null }
    else {
        $inm = "$(& $uf 'identityNames')".Trim().ToLowerInvariant(); $inmd = "$(& $uf 'identityNamesDetail')".Trim()
        switch ($inm) {
            'ok'      { & $set 'identity-names' 'ok' $(if ($inmd) { $inmd } else { 'every role runs as id-pim-<role> and no old identity holds rights' }) $upAt }
            'missing' { & $set 'identity-names' 'missing' $(if ($inmd) { $inmd } else { 'a role does not run as id-pim-<role>, or an old identity still holds rights' }) $upAt }
            'n/a'     { & $set 'identity-names' 'n/a' $(if ($inmd) { $inmd } else { 'no container app or job uses a managed identity' }) $upAt }
            default   { & $set 'identity-names' 'unknown' $(if ($inmd) { "not determined: $inmd" } else { 'not checked by this version' }) $upAt }
        }
    }

    # ---- assemble, in the catalog's order; validate; cap -------------------------------------------------------------
    # WAITING-CUSTOMER (framework, Invardia 2026-11-08): a step that is still MISSING and has a customer ticket recorded
    # (pim.Settings 'SetupStepTickets' { "<key>": "SUP-yyyy-nnnnn" }) reports 'waiting-customer' + ticket -- counted apart from
    # the gaps. Only while it is missing: once the live read says ok, the ticket no longer matters. A malformed id is ignored.
    $tkt = ConvertTo-PimSetupStepObject (Get-PimSetupStepField $Facts 'Tickets')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in (Get-PimSetupStepCatalog)) {
        $r = $res[$c.key]
        if (-not $r) { $r = @{ state = 'unknown'; detail = 'not read'; at = $null } }
        $e = [ordered]@{ key = $c.key; title = $c.title; state = "$($r.state)"; since = $c.since; how = $c.how
                         checkedAt = (& $iso $r.at); detail = (ConvertTo-PimSetupStepDetail -Text $r.detail) }
        $tid = "$(Get-PimSetupStepField $tkt $c.key)".Trim()
        if ($e.state -eq 'missing' -and (Test-PimSetupStepTicketId -Id $tid)) {
            $e.state = 'waiting-customer'; $e['ticket'] = $tid
            $e.detail = ConvertTo-PimSetupStepDetail -Text "waiting for the customer ($tid): $($r.detail)"
        }
        if (Test-PimSetupStepEntry -Entry $e) { $out.Add($e) }
        if ($out.Count -ge (Get-PimSetupStepMax)) { break }
    }
    return @($out.ToArray())
}

# ---------------------------------------------------------------------------------------------------------------------
# THE HEARTBEAT SIDE
# ---------------------------------------------------------------------------------------------------------------------
function Test-PimUplinkSetupStepsOn {
    # PURE. PIM_UPLINK_SETUPSTEPS: ON by default (Invardia ignores what it does not know); 0 / false / off / no = off.
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_SETUPSTEPS)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function Add-PimUplinkSetupStepsField {
    <#
      Puts setupSteps on the heartbeat -Record and PROVES the record's JSON text (a JSON array of objects, under Windows
      PowerShell 5.1 too -- the Controls lesson): not an array = the field is removed with one warning. Never throws.
      Returns $true when it went on.
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][object[]]$Steps)
    $s = @(@($Steps) | Where-Object { Test-PimSetupStepEntry -Entry $_ })
    if (-not $s.Count) { return $false }
    try {
        $Record | Add-Member -NotePropertyName 'setupSteps' -NotePropertyValue ([object[]]$s) -Force
        $t = ''; try { $t = "$($Record | ConvertTo-Json -Depth 6 -Compress)" } catch { $t = '' }
        if ($t.Contains('"setupSteps":[{')) { return $true }
        $Record.PSObject.Properties.Remove('setupSteps')
        Write-Warning '[uplink] setupSteps could not be written as a JSON array -- the heartbeat goes without it.'
    } catch { try { $Record.PSObject.Properties.Remove('setupSteps') } catch { } }
    return $false
}

# ---------------------------------------------------------------------------------------------------------------------
# THE UPDATER SIDE (I/O through seams; READ ONLY; never throws)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSetupStepUpdaterFacts {
    <#
      The updater's facts for setupSteps, gathered during its converge (update-job-entry step 2g) and stored in
      pim.Settings 'UpdateState'.setupFacts. READ ONLY: ARM GET + one SQL scalar; every read that fails leaves its fact $null
      (= unknown), never a guess. Never throws.
        -Arm       { param($method, $path, $body) } -- called with 'GET' only
        -SqlScalar { param($sql) }                   -- one read-only scalar ($null = no store)
        -ConvergeLines   Invoke-PimUpdateConvergeDefaults .lines
        -JobSelfId       Invoke-PimJobSelfIdUpdate result
        -SqlAudit        Invoke-PimSqlAuditConverge result
        -AsBuilt         Invoke-PimAsBuiltConverge result
        -DbInit          Invoke-PimDbInitJobConverge result (OPEN-06; $null = not converged this run -> db-job unknown)
        -SourceUrl       PIM_UPDATE_SOURCE_URL
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$SqlScalar,
          [object[]]$ConvergeLines = @(), [AllowNull()][object]$JobSelfId, [AllowNull()][object]$SqlAudit, [AllowNull()][object]$AsBuilt,
          [AllowNull()][object]$DbInit,
          [AllowNull()][string]$SourceUrl = $env:PIM_UPDATE_SOURCE_URL, [datetime]$NowUtc = [datetime]::UtcNow)
    $f = [ordered]@{ checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
                     privateNetwork = $null; jobsOperator = $null; tickJobIdSet = $null
                     acrAdminOff = $null; kvPurgeProtection = $null; sourceUrlNoSas = $null; sqlAudit = $null
                     frontKey = $null; frontSqlSchema = $null; frontKvPrivate = $null; jobSelfReader = $null
                     asBuiltStorage = 'unknown'; asBuiltRights = 'unknown'; asBuiltDetail = ''
                     dbJob = 'unknown'; dbJobDetail = '' }
    try { $dj = Get-PimSetupStepDbJobFacts -DbInitResult $DbInit; $f.dbJob = $dj.dbJob; $f.dbJobDetail = (ConvertTo-PimSetupStepDetail -Text $dj.dbJobDetail) } catch { }
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $items = { param($a) if ($null -eq $a) { @() } elseif ($a.PSObject.Properties['value']) { @(@($a.value) | Where-Object { $_ }) } else { @($a) } }
    try { $cl = ConvertFrom-PimSetupConvergeLines -Lines $ConvergeLines; $f.jobsOperator = $cl.jobsOperator; $f.tickJobIdSet = $cl.tickJobIdSet } catch { }
    try { $f.jobSelfReader = ConvertFrom-PimSetupJobSelfIdResult -Result $JobSelfId } catch { }
    try { $f.sqlAudit = ConvertFrom-PimSetupSqlAuditResult -Result $SqlAudit } catch { }
    try { $f.sourceUrlNoSas = [bool](Test-PimUpdateSourceUrlNoSas -Url $SourceUrl) } catch { }
    try { $ab = Get-PimSetupStepAsBuiltFacts -AsBuiltResult $AsBuilt; $f.asBuiltStorage = $ab.asBuiltStorage; $f.asBuiltRights = $ab.asBuiltRights; $f.asBuiltDetail = (ConvertTo-PimSetupStepDetail -Text $ab.asBuiltDetail) } catch { }
    # private network: the Manager app -> its environment -> vnetConfiguration.internal
    try {
        $app = & $Arm 'GET' "$rg/providers/Microsoft.App/containerApps/$ManagerApp`?api-version=2024-03-01" $null
        $envId = "$($app.properties.managedEnvironmentId)".Trim(); if (-not $envId) { $envId = "$($app.properties.environmentId)".Trim() }
        if ($envId) {
            $env1 = & $Arm 'GET' "$envId`?api-version=2024-03-01" $null
            $int = ConvertTo-PimSetupStepBool $env1.properties.vnetConfiguration.internal
            $f.privateNetwork = $(if ($int -eq $true) { $true } else { $false })
        }
    } catch { }
    # CR8: the registries in the resource group -- every one with the admin user off
    try {
        $regs = @(& $items (& $Arm 'GET' "$rg/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01" $null))
        if ($regs.Count) { $f.acrAdminOff = -not [bool](@($regs | Where-Object { (ConvertTo-PimSetupStepBool $_.properties.adminUserEnabled) -eq $true }).Count) }
    } catch { }
    # CR8 purge protection, the front's private vault, the front key: the vaults in the resource group
    try {
        $kvs = @(& $items (& $Arm 'GET' "$rg/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01" $null))
        if (-not $kvs.Count) { $f.frontKvPrivate = 'none' }
        else {
            $f.kvPurgeProtection = -not [bool](@($kvs | Where-Object { (ConvertTo-PimSetupStepBool $_.properties.enablePurgeProtection) -ne $true }).Count)
            $priv = @($kvs | Where-Object { "$($_.properties.publicNetworkAccess)" -ieq 'Disabled' })
            if (-not $priv.Count) { $f.frontKvPrivate = 'public' }
            elseif (@($priv | Where-Object { @($_.properties.privateEndpointConnections | Where-Object { $_ }).Count -eq 0 }).Count) { $f.frontKvPrivate = 'private-no-endpoint' }
            else { $f.frontKvPrivate = 'private' }
            $found = $false; $unread = $false
            foreach ($kv in $kvs) {
                try { $k = & $Arm 'GET' "$rg/providers/Microsoft.KeyVault/vaults/$($kv.name)/keys/signin-front?api-version=2023-07-01" $null; if ($k) { $found = $true; break } }
                catch { if ("$($_.Exception.Message)" -notmatch '(?i)\b404\b|NotFound|KeyNotFound') { $unread = $true } }
            }
            $f.frontKey = $(if ($found) { $true } elseif ($unread) { $null } else { $false })
        }
    } catch { }
    # the front's database schema
    if ($SqlScalar) {
        try { $v = & $SqlScalar "SELECT CASE WHEN SCHEMA_ID(N'signin') IS NULL THEN 0 ELSE 1 END"; $b = ConvertTo-PimSetupStepBool $v; if ($b -is [bool]) { $f.frontSqlSchema = $b } } catch { }
    }
    return $f
}
