#Requires -Version 5.1
<#
.SYNOPSIS
  JOB-RENAME on an install whose database is PRIVATE (public network access off): pim.Settings 'SchedulerTickJobId' and
  'InstallNames' are read and written by a ONE-TIME Container Apps job inside the install's own environment, because the
  Invardia Support app's audited SQL cannot reach a private database from outside. Used by Rename-PimJobs.ps1 -SqlViaJob
  and its offline test (tests/Test-PimJobRenameSqlJob.ps1).

.DESCRIPTION
  The pattern of Invoke-PimSupportSqlAccessJob.ps1 (tools/setup/_PimSupportSqlJob.ps1), for this one purpose:
    1. read the install's database job (caj-pim-dbinit, else ca-pim-dbinit): its environment, its image, the SQL server and
       database it names, and the user-assigned identity it signs in to SQL with (PIM_DBINIT_MI_CLIENT_ID among the
       identities it carries). That identity is the SQL server's administrator (or a member of the SQL admin group) --
       tools/pim-engine/dbinit-job-entry.ps1 creates the database's users and schema with it -- so it may read and write
       pim.Settings. It is used as it is: no role, no group membership and no permission is given to any identity.
    2. a job of the one-time name that a killed run of THIS step left behind (its tag says so) is removed first; any other
       job of that name is not touched and stops the run
    3. create the one-time job (caj-pim-renamesql) in the same environment with that identity, start it once, wait
    4. read its result from its console lines (Log Analytics): ONE line "[jobrename-sql] RESULT {json}" carrying this run's
       id, the values of both settings base64-encoded
    5. ALWAYS, also after a failed step: remove the one-time job and read back that it is gone.

  THE SCRIPT THE JOB RUNS IS FIXED TEXT (Get-PimJobRenameSqlJobScript): the same text for every read and every write. What
  it does comes only from its environment values: PIM_RENAMESQL_OP (read | write), PIM_RENAMESQL_NAME (a write: one of the
  two allowed names, checked again inside the job), PIM_RENAMESQL_VALUE_B64 (a write: the JSON value, UTF-8 + base64) and
  PIM_RENAMESQL_RUN_ID. The value never becomes part of a statement: the job sends it as a parameter (@value) of a fixed
  UPDATE, and only when no row was updated a fixed INSERT (a MERGE needs INSERT rights even for an update). A read reads
  both allowed names in one run; a write reads both back in the same run.

  THE SEAM (Invoke-PimJobRenameSqlJobSeam) is the -Sql seam of Rename-PimJobs.ps1: param($a, $n, $v), $a 'get' | 'set',
  $n one of the two allowed names. A 'get' is served from the last run's values when that name was not served from them
  yet (the library reads the two names one after the other: one run answers both); otherwise it starts a read run. A
  'set' is one write run whose read-back answers the next 'get' of each name. A missing row reads as $null.

  Every caller hands in:
    -Arm  { param($Method, $Path, $Body) }       ARM, the path carries its api-version; throws "... HTTP <code> ..."
    -Logs { param($WorkspaceId, $Execution) }    the console lines of one execution (Log Analytics); may return none
  Needs _PimSupportSqlJob.ps1 loaded first (its pure helpers: the api version, the tag name, the JSON map, the job command,
  the log query, the database job's identity setting, the image's product folder).
#>

function Get-PimJobRenameSqlJobName { return 'caj-pim-renamesql' }
function Get-PimJobRenameSqlJobTagValue { return 'job-rename-sql' }
function Get-PimJobRenameSqlJobSettingNames { return @('SchedulerTickJobId', 'InstallNames') }
function Get-PimJobRenameSqlJobTemplateNames { return @('caj-pim-dbinit', 'ca-pim-dbinit') }
function Get-PimJobRenameSqlJobMarker { return '[jobrename-sql]' }

function Test-PimJobRenameSqlJobSettingName {
    # PURE. $true only for one of the two allowed names, exactly as written (case-sensitive).
    param([AllowNull()][AllowEmptyString()][string]$Name)
    return [bool](@(Get-PimJobRenameSqlJobSettingNames) -ccontains "$Name")
}

function ConvertTo-PimJobRenameSqlJobValue {
    # PURE. The value of a write as the job receives it: its JSON text (ConvertTo-Json, as the audited SQL path writes it), UTF-8, base64.
    param([AllowNull()]$Value)
    $j = ConvertTo-Json -InputObject $Value -Compress -Depth 8
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$j"))
}

function ConvertFrom-PimJobRenameSqlJobSetting {
    # PURE. One setting of the result line -> its value: $null for a missing row (or an empty value), else the JSON parsed (the raw text when it is not JSON).
    param([AllowNull()]$Entry)
    if ($null -eq $Entry -or -not [bool]$Entry.present) { return $null }
    $raw = ''
    try { $raw = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($Entry.b64)")) } catch { throw 'the result line carries a value that is not base64' }
    if (-not $raw.Trim()) { return $null }
    try { return ($raw | ConvertFrom-Json) } catch { return $raw }
}

function Get-PimJobRenameSqlJobScript {
    <#
      PURE. The PowerShell the one-time job runs. FIXED TEXT: no name, no value and no run id is ever put into it (only the
      image's product folder, read off the database job's own start command). The token client and the SQL client of the
      image (engine/_shared/PIM-Rest.ps1 + PIM-SqlStore.ps1, in every image that has the database job), the managed identity
      named in PIM_RENAMESQL_MI_CLIENT_ID, parameterised statements only, ONE result line, exit 0 only when it read back.
    #>
    param([string]$AppRoot = (Get-PimSupportSqlJobDefaultAppRoot))
    $root = "$AppRoot".Trim().TrimEnd('/')
    if ($root -notmatch '^[A-Za-z0-9_./:~ -]+$') { throw "Get-PimJobRenameSqlJobScript: '$AppRoot' is not a safe folder path." }
    $main = @'
$ErrorActionPreference = 'Stop'
$rc = 1
$op = ''; $name = ''; $runId = ''
function Write-RenameSqlLine { param([string]$Message) Write-Host ('[jobrename-sql] ' + $Message) }
function Add-RenameSqlParameter {
    param($Command, [string]$ParameterName, $Value, [int]$Size)
    $p = $Command.CreateParameter()
    $p.ParameterName = $ParameterName
    $p.DbType = [System.Data.DbType]::String
    $p.Size = $Size
    $p.Value = $(if ($null -eq $Value) { [DBNull]::Value } else { [string]$Value })
    [void]$Command.Parameters.Add($p)
}
try {
    $allowed = @('SchedulerTickJobId', 'InstallNames')
    $op = "$($env:PIM_RENAMESQL_OP)".Trim().ToLowerInvariant()
    $name = "$($env:PIM_RENAMESQL_NAME)".Trim()
    $runId = "$($env:PIM_RENAMESQL_RUN_ID)".Trim()
    Write-RenameSqlLine "start: pim.Settings for the job rename (PIM Manager, one-time job), $op"
    if ($op -notin @('read', 'write')) { throw "PIM_RENAMESQL_OP '$op' is not read or write -- nothing was changed" }
    if ($runId -notmatch '^[0-9a-f]{32}$') { throw 'PIM_RENAMESQL_RUN_ID is not set -- nothing was changed' }
    $json = $null
    if ($op -eq 'write') {
        if ($allowed -cnotcontains $name) { throw "refusing pim.Settings '$name' (this step writes SchedulerTickJobId and InstallNames only) -- nothing was changed" }
        try { $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($env:PIM_RENAMESQL_VALUE_B64)")) } catch { throw 'PIM_RENAMESQL_VALUE_B64 is not base64 -- nothing was changed' }
        if (-not "$json".Trim()) { throw 'PIM_RENAMESQL_VALUE_B64 carries no value -- nothing was changed' }
        try { $null = ConvertFrom-Json -InputObject $json } catch { throw 'the value is not JSON -- nothing was changed' }
    }
    . '__APPROOT__/engine/_shared/PIM-Rest.ps1'
    . '__APPROOT__/engine/_shared/PIM-SqlStore.ps1'
    $server = "$($env:PIM_SqlServer)".Trim()
    $database = "$($env:PIM_SqlDatabase)".Trim()
    if (-not $database) { $database = 'PimPlatform' }
    $miClientId = "$($env:PIM_RENAMESQL_MI_CLIENT_ID)".Trim()
    if (-not $server -or -not $miClientId) { throw 'PIM_SqlServer and PIM_RENAMESQL_MI_CLIENT_ID must both be set -- nothing was changed' }
    $global:PIM_ManagedIdentityClientId = $miClientId
    Write-RenameSqlLine "database $server / $database, signing in as the managed identity $miClientId"
    $conn = New-PimSqlConnection -ConnectionString "Server=tcp:$server,1433;Database=$database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60"
    $conn.Open()
    $updated = 0; $inserted = 0
    $settings = [ordered]@{}
    try {
        if ($op -eq 'write') {
            # UPDATE first; INSERT only when the row is missing (one combined statement would need INSERT rights even to update)
            $up = $conn.CreateCommand(); $up.CommandTimeout = 120
            $up.CommandText = 'UPDATE pim.Settings SET ValueJson = @value, UpdatedUtc = SYSUTCDATETIME() WHERE Name = @name'
            Add-RenameSqlParameter -Command $up -ParameterName '@name' -Value $name -Size 200
            Add-RenameSqlParameter -Command $up -ParameterName '@value' -Value $json -Size -1
            $updated = [int]$up.ExecuteNonQuery()
            if ($updated -eq 0) {
                $ins = $conn.CreateCommand(); $ins.CommandTimeout = 120
                $ins.CommandText = 'INSERT INTO pim.Settings (Name, ValueJson, UpdatedUtc) VALUES (@name, @value, SYSUTCDATETIME())'
                Add-RenameSqlParameter -Command $ins -ParameterName '@name' -Value $name -Size 200
                Add-RenameSqlParameter -Command $ins -ParameterName '@value' -Value $json -Size -1
                $inserted = [int]$ins.ExecuteNonQuery()
            }
            Write-RenameSqlLine "wrote pim.Settings '$name' (updated $updated, inserted $inserted)"
        }
        foreach ($n in $allowed) {
            $rd = $conn.CreateCommand(); $rd.CommandTimeout = 120
            $rd.CommandText = 'SELECT ValueJson FROM pim.Settings WHERE Name = @name'
            Add-RenameSqlParameter -Command $rd -ParameterName '@name' -Value $n -Size 200
            $v = $rd.ExecuteScalar()
            $has = ($null -ne $v -and $v -isnot [DBNull])
            $settings[$n] = [ordered]@{ present = $has; b64 = $(if ($has) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$v)) } else { '' }) }
        }
    } finally { $conn.Close() }
    if ($op -eq 'write') {
        $back = ''
        if ($settings[$name].present) { $back = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($settings[$name].b64)) }
        if ($back -cne $json) { throw "pim.Settings '$name' does not read back as written" }
    }
    $result = [ordered]@{ ok = $true; runId = $runId; op = $op; name = $name; updated = $updated; inserted = $inserted; settings = $settings }
    Write-RenameSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 5))
    $rc = 0
} catch {
    $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim()
    Write-RenameSqlLine ('ERROR ' + $m)
    $failed = [ordered]@{ ok = $false; runId = $runId; op = $op; name = $name; problem = $m }
    Write-RenameSqlLine ('RESULT ' + ($failed | ConvertTo-Json -Compress))
}
exit $rc
'@
    return $main.Replace('__APPROOT__', $root)
}

function ConvertFrom-PimJobRenameSqlJobLog {
    # PURE. The console lines of the execution -> @{ lines (no blanks, no colour codes); result (the LAST RESULT line of THIS run id, or $null) }.
    param([AllowNull()][string[]]$Lines, [string]$RunId = '')
    $out = [System.Collections.Generic.List[string]]::new()
    $res = $null
    foreach ($x in @($Lines)) {
        $t = ("$x" -replace '\x1b\[[0-9;]*m', '').TrimEnd()
        if (-not $t.Trim()) { continue }
        $out.Add($t)
        if ($t -match '^\s*\[jobrename-sql\] RESULT (\{.*\})\s*$') {
            $o = $null
            try { $o = $Matches[1] | ConvertFrom-Json } catch { $o = $null }
            if ($o -and (-not "$RunId" -or "$($o.runId)" -eq "$RunId")) { $res = $o }
        }
    }
    return @{ lines = @($out.ToArray()); result = $res }
}

function ConvertTo-PimJobRenameSqlJobServer {
    # PURE. A server name as the jobs carry it: 'x' -> 'x.database.windows.net'; lower-case; '' stays ''.
    param([AllowNull()][string]$Server)
    $s = "$Server".Trim().ToLowerInvariant()
    if ($s -and $s -notmatch '\.') { $s = "$s.database.windows.net" }
    return $s
}

function Get-PimJobRenameSqlJobPlan {
    <#
      PURE. From the install's database job (-Template, the ARM object) to the one-time job for ONE read or write: which
      identity, which database, which image, the environment values and the whole resource body. Never throws.
      Returns { ok; problem; identityResourceId; identityName; identityClientId; pullIdentities; sqlServer; sqlDatabase;
                image; environmentId; location; appRoot; script; env (name -> value); resource }.
      ok = $false + problem: the database job cannot be used WITHOUT giving some identity a new right, the name is not
      allowed, or the server named by the caller is not the one the database job administers -- the caller stops.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Template,
        [Parameter(Mandatory)][string]$TemplateJobName,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][ValidateSet('read', 'write')][string]$Op,
        [string]$Name = '',
        [AllowNull()]$Value = $null,
        [Parameter(Mandatory)][string]$RunId,
        [string]$SqlServer = '',
        [string]$SqlDatabase = ''
    )
    $p = [ordered]@{ ok = $false; problem = ''; identityResourceId = ''; identityName = ''; identityClientId = ''; pullIdentities = @()
                     sqlServer = ''; sqlDatabase = ''; image = ''; environmentId = ''; location = ''; appRoot = ''; script = ''; env = [ordered]@{}; resource = $null }
    try {
        if ($Op -eq 'write' -and -not (Test-PimJobRenameSqlJobSettingName -Name $Name)) { $p.problem = "refusing pim.Settings '$Name' (this step writes SchedulerTickJobId and InstallNames only)"; return [pscustomobject]$p }
        if ($Op -eq 'read' -and "$Name" -and -not (Test-PimJobRenameSqlJobSettingName -Name $Name)) { $p.problem = "refusing pim.Settings '$Name' (this step reads SchedulerTickJobId and InstallNames only)"; return [pscustomobject]$p }
        if ("$RunId" -notmatch '^[0-9a-f]{32}$') { $p.problem = "'$RunId' is not a run id"; return [pscustomobject]$p }
        if ("$JobName" -cnotmatch '^[a-z][a-z0-9-]{0,30}[a-z0-9]$') { $p.problem = "'$JobName' is not a job name (lower-case letters, digits and '-', at most 32 characters)"; return [pscustomobject]$p }
        if ("$JobName" -ieq "$TemplateJobName" -or @(Get-PimJobRenameSqlJobTemplateNames) -contains "$JobName".ToLowerInvariant()) { $p.problem = "the one-time job cannot have the name of a database job ('$JobName')"; return [pscustomobject]$p }
        if (-not $Template -or -not $Template.properties) { $p.problem = "the job '$TemplateJobName' could not be read"; return [pscustomobject]$p }
        $p.environmentId = "$($Template.properties.environmentId)".Trim()
        $p.location = "$($Template.location)".Trim()
        if (-not $p.environmentId -or -not $p.location) { $p.problem = "the job '$TemplateJobName' names no Container Apps environment or no location"; return [pscustomobject]$p }

        $containers = @(@($Template.properties.template.containers) | Where-Object { $_ })
        $c = @($containers | Where-Object { "$($_.name)" -eq $TemplateJobName }) | Select-Object -First 1
        if (-not $c) { $c = $containers | Select-Object -First 1 }
        if (-not $c -or -not "$($c.image)".Trim()) { $p.problem = "the job '$TemplateJobName' has no container image"; return [pscustomobject]$p }
        $p.image = "$($c.image)".Trim()
        $envMap = [ordered]@{}
        foreach ($e in @($c.env)) { if ($e -and "$($e.name)".Trim()) { $envMap["$($e.name)".Trim()] = "$($e.value)" } }
        $p.sqlServer = "$($envMap['PIM_SqlServer'])".Trim()
        $p.sqlDatabase = "$($envMap['PIM_SqlDatabase'])".Trim()
        if (-not $p.sqlDatabase) { $p.sqlDatabase = 'PimPlatform' }
        if ($p.sqlServer -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{1,250}$') { $p.problem = "the job '$TemplateJobName' does not name the SQL server (its setting PIM_SqlServer)"; return [pscustomobject]$p }
        if ($p.sqlDatabase -notmatch '^[^<>*%&:\\/?\[\]'';]{1,128}$') { $p.problem = "the job '$TemplateJobName' names a database that is not a database name"; return [pscustomobject]$p }
        # the identity administers THE DATABASE ITS JOB NAMES: a server / database the caller names must be that one
        if ("$SqlServer".Trim() -and (ConvertTo-PimJobRenameSqlJobServer $SqlServer) -ne (ConvertTo-PimJobRenameSqlJobServer $p.sqlServer)) { $p.problem = "the SQL server '$SqlServer' is not the one the job '$TemplateJobName' names ($($p.sqlServer)) -- its identity is only known to administer that one"; return [pscustomobject]$p }
        if ("$SqlDatabase".Trim() -and "$SqlDatabase".Trim() -ine $p.sqlDatabase) { $p.problem = "the database '$SqlDatabase' is not the one the job '$TemplateJobName' names ($($p.sqlDatabase))"; return [pscustomobject]$p }

        # ---- the identity: one the database job ALREADY carries, found by its client id. Never a new one.
        $setting = Get-PimSupportSqlJobIdentitySetting
        $cid = "$($envMap[$setting])".Trim().ToLowerInvariant()
        $ua = ConvertTo-PimSupportSqlJobMap $(if ($Template.identity) { $Template.identity.userAssignedIdentities } else { $null })
        if (-not $cid) { $p.problem = "the job '$TemplateJobName' does not say which identity it signs in to the database with (no setting $setting) -- there is no identity of this install this step may use"; return [pscustomobject]$p }
        $sqlKey = ''
        foreach ($k in @($ua.Keys)) { if ("$($ua[$k].clientId)".Trim().ToLowerInvariant() -eq $cid) { $sqlKey = "$k"; break } }
        if (-not $sqlKey) { $p.problem = "the identity $cid is not one of the user-assigned identities of the job '$TemplateJobName' -- this step never attaches an identity the install's own job does not already carry"; return [pscustomobject]$p }
        $p.identityResourceId = $sqlKey; $p.identityName = ($sqlKey -split '/')[-1]; $p.identityClientId = $cid

        # ---- the image pull: only with a user-assigned identity the database job already carries
        $uaBody = [ordered]@{}; $uaBody[$sqlKey] = @{}
        $regs = [System.Collections.Generic.List[object]]::new()
        $pull = [System.Collections.Generic.List[string]]::new()
        foreach ($r in @(@($Template.properties.configuration.registries) | Where-Object { $_ })) {
            $server = "$($r.server)".Trim(); $ri = "$($r.identity)".Trim()
            if ("$($r.passwordSecretRef)".Trim() -or "$($r.username)".Trim()) { $p.problem = "the job '$TemplateJobName' pulls its image from $server with a user name and password -- a one-time job would need a copy of that password, and this step copies no secret"; return [pscustomobject]$p }
            if (-not $ri -or $ri -ieq 'system') { $p.problem = "the job '$TemplateJobName' pulls its image from $server with its OWN system identity -- a new job has another identity, which would need a new right on the registry"; return [pscustomobject]$p }
            $pk = ''
            foreach ($k in @($ua.Keys)) { if ("$k" -ieq $ri) { $pk = "$k"; break } }
            if (-not $pk) { $p.problem = "the job '$TemplateJobName' pulls its image from $server with an identity it does not carry ($ri)"; return [pscustomobject]$p }
            if (-not $uaBody.Contains($pk)) { $uaBody[$pk] = @{} }
            if ($pk -ine $sqlKey -and -not $pull.Contains($pk)) { $pull.Add($pk) }
            $regs.Add([ordered]@{ server = $server; identity = $pk })
        }
        $p.pullIdentities = @($pull.ToArray())

        # ---- where the image keeps the product: read off the database job's own start command
        $root = Get-PimSupportSqlJobDefaultAppRoot
        foreach ($a in @($c.args)) { if ("$a" -match '^(?<root>[A-Za-z0-9_./:~ -]+)/tools/pim-engine/[A-Za-z0-9_.-]+\.ps1$') { $root = $Matches['root']; break } }
        $p.appRoot = $root
        $p.script = Get-PimJobRenameSqlJobScript -AppRoot $root
        $encoded = ConvertTo-PimSupportSqlJobCommand -Script $p.script

        $ev = [ordered]@{ PIM_SqlServer = $p.sqlServer; PIM_SqlDatabase = $p.sqlDatabase; PIM_RENAMESQL_MI_CLIENT_ID = $cid; PIM_RENAMESQL_OP = $Op; PIM_RENAMESQL_RUN_ID = "$RunId" }
        if ($Op -eq 'write') { $ev['PIM_RENAMESQL_NAME'] = "$Name"; $ev['PIM_RENAMESQL_VALUE_B64'] = (ConvertTo-PimJobRenameSqlJobValue -Value $Value) }
        $p.env = $ev
        # replicaTimeout: the product's floor for every job (OPEN-27 / TenantSizing L7: never below 604800); the one-time job is
        # removed after its run anyway, so the long ceiling costs nothing
        $cfg = [ordered]@{ triggerType = 'Manual'; replicaTimeout = 604800; replicaRetryLimit = 0; manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } }
        if ($regs.Count) { $cfg['registries'] = @($regs.ToArray()) }
        $props = [ordered]@{ environmentId = $p.environmentId }
        if ("$($Template.properties.workloadProfileName)".Trim()) { $props['workloadProfileName'] = "$($Template.properties.workloadProfileName)".Trim() }
        $props['configuration'] = $cfg
        $props['template'] = @{ containers = @(@{
            name      = $JobName
            image     = $p.image
            command   = @('pwsh')
            args      = @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
            env       = @(foreach ($k in @($ev.Keys)) { @{ name = "$k"; value = "$($ev[$k])" } })
            resources = @{ cpu = 0.5; memory = '1.0Gi' }
        }) }
        $tags = @{}; $tags[(Get-PimSupportSqlJobTagName)] = (Get-PimJobRenameSqlJobTagValue)
        $p.resource = [ordered]@{ location = $p.location; tags = $tags; identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uaBody }; properties = $props }
        $p.ok = $true
    } catch { $p.ok = $false; $p.problem = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
    return [pscustomobject]$p
}

function Get-PimJobRenameSqlJobLogLines {
    # READ. The console lines of one execution from the environment's Log Analytics workspace (REST, the shared token client).
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Execution)
    if ("$WorkspaceId" -notmatch '^[0-9a-fA-F-]{36}$') { throw "'$WorkspaceId' is not a Log Analytics workspace id" }
    $q = Get-PimSupportSqlJobLogQuery -Execution $Execution
    $r = Invoke-PimRest -Method 'POST' -Url "https://api.loganalytics.io/v1/workspaces/$WorkspaceId/query" -Resource 'https://api.loganalytics.io' -Body @{ query = $q; timespan = 'P1D' }
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($t in @(@($r.tables) | Select-Object -First 1)) {
        $at = 0; $cols = @($t.columns)
        for ($i = 0; $i -lt $cols.Count; $i++) { if ("$($cols[$i].name)" -eq 'Log_s') { $at = $i } }
        foreach ($row in @($t.rows)) { $out.Add("$(@($row)[$at])") }
    }
    return @($out.ToArray())
}

function Invoke-PimJobRenameSqlJob {
    <#
      ONE read or write of pim.Settings through the one-time job, end to end (see the file header). Never throws.
      Returns { ok; op; name; runId; templateJobName; plan; leftover; jobCreated; jobRemoved; execution; status; logLines;
                result; values (name -> value, $null = missing row); problems }.
      ok only when: the execution Succeeded, its result line (this run id) says ok, and the one-time job is gone again.
      -WhatIfOnly: the database job is READ and the plan made; nothing is created.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Arm,
        [scriptblock]$Logs,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][ValidateSet('read', 'write')][string]$Op,
        [string]$Name = '',
        [AllowNull()]$Value = $null,
        [string]$JobName = (Get-PimJobRenameSqlJobName),
        [string]$TemplateJobName = '',
        [string]$SqlServer = '',
        [string]$SqlDatabase = '',
        [int]$TimeoutSeconds = 600,
        [int]$PollSeconds = 10,
        [int]$LogWaitSeconds = 300,
        [int]$ReadBackTries = 30,
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds },
        [switch]$WhatIfOnly
    )
    $api = Get-PimSupportSqlJobAcaApi
    $tagName = Get-PimSupportSqlJobTagName; $tagValue = Get-PimJobRenameSqlJobTagValue
    $rgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $jobPath = "$rgPath/providers/Microsoft.App/jobs/$JobName"
    $notFound = '(?i)HTTP 404\b|ResourceNotFound|was not found|NotFound'
    $problems = [System.Collections.Generic.List[string]]::new()
    $runId = [guid]::NewGuid().ToString('N')
    $res = [ordered]@{ ok = $false; op = $Op; name = "$Name"; runId = $runId; templateJobName = ''; plan = $null; leftover = $false; jobCreated = $false; jobRemoved = $false
                       execution = ''; status = ''; logLines = @(); result = $null; values = @{}; problems = @() }
    $say = { param([string]$m, [string]$c = 'DarkGray') Write-Host "    [sql job] $m" -ForegroundColor $c }
    $first = { param($e) (("$($e.Exception.Message)" -split "`n")[0]).Trim() }
    $get = {
        param([string]$P)
        try { return (& $Arm 'GET' "${P}?api-version=$api" $null) }
        catch { if ("$($_.Exception.Message)" -match $notFound) { return $null }; throw }
    }
    $finish = {
        $res.problems = @($problems.ToArray())
        $res.ok = (-not $problems.Count)
        return [pscustomobject]$res
    }
    $remove = {
        # DELETE the one-time job and read back until it is gone. '' = gone; otherwise why it is not.
        $why = ''
        for ($i = 0; $i -lt [Math]::Max(1, $ReadBackTries); $i++) {
            if ($i -eq 0 -or $i -eq 5) {
                try { [void](& $Arm 'DELETE' "${jobPath}?api-version=$api" $null) }
                catch { if ("$($_.Exception.Message)" -notmatch $notFound) { $why = & $first $_ } }
            }
            try { if (-not (& $get $jobPath)) { return '' } } catch { $why = & $first $_ }
            & $Sleep 5
        }
        if ($why) { return $why }
        return 'it is still there'
    }

    # ---- 0. the name: the allow-list holds before anything is read
    if ($Op -eq 'write' -and -not (Test-PimJobRenameSqlJobSettingName -Name $Name)) { $problems.Add("refusing pim.Settings '$Name' (this step writes SchedulerTickJobId and InstallNames only) -- nothing was read or changed"); return (& $finish) }
    if ($Op -eq 'read' -and "$Name" -and -not (Test-PimJobRenameSqlJobSettingName -Name $Name)) { $problems.Add("refusing pim.Settings '$Name' (this step reads SchedulerTickJobId and InstallNames only) -- nothing was read or changed"); return (& $finish) }
    # the result comes back ONLY through the log lines: without a reader nothing is started (a write would be unconfirmed)
    if (-not $Logs -and -not $WhatIfOnly) { $problems.Add('no log reader: the one-time job''s result could not be read, so no job is started -- nothing was changed'); return (& $finish) }

    # ---- 1. the install's database job (read fresh every run: a rename of the database job moves it), and the plan
    $tpl = $null; $tplName = "$TemplateJobName".Trim()
    $cands = if ($tplName) { @($tplName) } else { @(Get-PimJobRenameSqlJobTemplateNames) }
    foreach ($tn in $cands) {
        try { $tpl = & $get "$rgPath/providers/Microsoft.App/jobs/$tn" }
        catch { $problems.Add("the job '$tn' could not be read in resource group '$ResourceGroup': $(& $first $_) -- nothing was changed"); return (& $finish) }
        if ($tpl) { $tplName = $tn; break }
    }
    $res.templateJobName = $tplName
    if (-not $tpl) { $problems.Add("this install has no database job ($($cands -join ' or ')) in resource group '$ResourceGroup' -- it is where a private database's administrator identity is kept; without it pim.Settings cannot be reached from inside. Nothing was changed."); return (& $finish) }
    $plan = Get-PimJobRenameSqlJobPlan -Template $tpl -TemplateJobName $tplName -JobName $JobName -Op $Op -Name $Name -Value $Value -RunId $runId -SqlServer $SqlServer -SqlDatabase $SqlDatabase
    $res.plan = $plan
    if (-not $plan.ok) { $problems.Add("$($plan.problem). Nothing was changed."); return (& $finish) }

    # ---- 2. a job of the one-time name: a leftover of this step goes first; any other is not touched
    try {
        $old = & $get $jobPath
        if ($old) {
            $tags = ConvertTo-PimSupportSqlJobMap $old.tags
            if ("$($tags[$tagName])" -ne $tagValue) { $problems.Add("a job named '$JobName' is already in resource group '$ResourceGroup' and was not made by this step (it does not carry the tag $tagName = $tagValue) -- it is not touched. Nothing was changed."); return (& $finish) }
            $res.leftover = $true
        }
    } catch { $problems.Add("could not read whether a job '$JobName' is already there: $(& $first $_) -- nothing was changed"); return (& $finish) }

    if ($WhatIfOnly) {
        Write-Host "What if: create the one-time job '$JobName' in the environment $(($plan.environmentId -split '/')[-1]) as $($plan.identityName) (the identity of $tplName), start it once to $(if ($Op -eq 'write') { "write pim.Settings '$Name' and read it back" } else { 'read pim.Settings SchedulerTickJobId and InstallNames' }), then remove it and read back that it is gone"
        return (& $finish)
    }
    if ($res.leftover) {
        $left = & $remove
        if ($left) { $problems.Add("the job '$JobName' an earlier run left behind could not be removed ($left) -- nothing else was changed"); return (& $finish) }
        & $say "removed: the job '$JobName' an earlier run left behind (read back)" 'Yellow'
    }

    $final = @('Succeeded', 'Failed', 'Degraded', 'Stopped')
    try {
        try {
            # ---- 3. create, start once, wait
            $res.jobCreated = $true     # set BEFORE the call: a job that was half created is still removed
            [void](& $Arm 'PUT' "${jobPath}?api-version=$api" $plan.resource)
            $state = ''
            $tries = [Math]::Max(1, [int][Math]::Ceiling(120 / [double][Math]::Max(1, $PollSeconds)))
            for ($i = 0; $i -lt $tries; $i++) {
                $j = & $get $jobPath
                $state = if ($j) { "$($j.properties.provisioningState)".Trim() } else { 'NotFound' }
                if ($state -in @('Succeeded', 'Failed', 'Canceled')) { break }
                & $Sleep $PollSeconds
            }
            if ($state -ne 'Succeeded') { throw "the job '$JobName' was not created (state: $state)" }
            & $say "created: the one-time job '$JobName' as $($plan.identityName) (the identity of $tplName; database $($plan.sqlServer) / $($plan.sqlDatabase))"
            $started = & $Arm 'POST' "${jobPath}/start?api-version=$api" @{}
            $exec = if ($started) { "$($started.name)".Trim() } else { '' }
            if (-not $exec) { throw "the job '$JobName' did not start (no execution was returned)" }
            $res.execution = $exec
            & $say "started: execution $exec ($Op$(if ($Op -eq 'write') { " '$Name'" })) -- waiting (at most $TimeoutSeconds seconds)"
            $tries = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSeconds / [double][Math]::Max(1, $PollSeconds)))
            $status = ''; $lastErr = ''
            for ($i = 0; $i -lt $tries; $i++) {
                & $Sleep $PollSeconds
                try { $x = & $get "$jobPath/executions/$exec"; $status = if ($x) { "$($x.properties.status)".Trim() } else { '' } } catch { $lastErr = & $first $_ }
                if ($status -in $final) { break }
            }
            $res.status = $status
            if ($status -notin $final) {
                try { [void](& $Arm 'POST' "${jobPath}/executions/$exec/stop?api-version=$api" @{}) } catch { }
                throw "the one-time job did not end within $TimeoutSeconds seconds (execution $exec, last state '$status'$(if ($lastErr) { ", last read: $lastErr" }))"
            }

            # ---- 4. the result line (the console lines reach the workspace a few minutes late)
            $lines = @()
            if ($Logs) {   # always set here (checked before the job was created)
                $ws = ''
                try { $envObj = & $get $plan.environmentId; if ($envObj) { $ws = "$($envObj.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim() } } catch { $ws = '' }
                if (-not $ws) { throw "the environment $(($plan.environmentId -split '/')[-1]) sends no console logs to a Log Analytics workspace, so the job's result cannot be read" }
                $ltries = [Math]::Max(1, [int][Math]::Ceiling($LogWaitSeconds / 20.0)); $refused = 0; $lastLogErr = ''
                for ($i = 0; $i -lt $ltries; $i++) {
                    try { $lines = @(& $Logs $ws $exec | ForEach-Object { "$_" }); $refused = 0 } catch { $lines = @(); $refused++; $lastLogErr = & $first $_ }
                    if ((ConvertFrom-PimJobRenameSqlJobLog -Lines $lines -RunId $runId).result) { break }
                    if ($refused -ge 2) { break }
                    if ($i -lt $ltries - 1) { & $Sleep 20 }
                }
                if ($refused -ge 2) { $problems.Add("the job's log lines could not be read (Log Analytics: $lastLogErr)") }
            } else { $problems.Add('no log reader: the job''s result cannot be read') }
            $log = ConvertFrom-PimJobRenameSqlJobLog -Lines $lines -RunId $runId
            $res.logLines = @($log.lines); $res.result = $log.result
            foreach ($ln in @($log.lines)) { Write-Host "      | $ln" -ForegroundColor DarkGray }
            $r = $log.result
            if (-not $r) {
                $problems.Add("the execution $exec ended '$status' but its result line ($(Get-PimJobRenameSqlJobMarker) RESULT, run $runId) could not be read within $LogWaitSeconds seconds -- $(if ($Op -eq 'write') { "the write of '$Name' is NOT confirmed" } else { 'pim.Settings is NOT read' })")
            } elseif (-not [bool]$r.ok) {
                $problems.Add("the one-time job says: $($r.problem)")
            } elseif ($status -ne 'Succeeded') {
                $problems.Add("the execution $exec ended '$status' -- treated as NOT done")
            } else {
                $vals = @{}
                foreach ($n in @(Get-PimJobRenameSqlJobSettingNames)) { $vals[$n] = ConvertFrom-PimJobRenameSqlJobSetting -Entry $r.settings.$n }
                $res.values = $vals
                & $say "$(if ($Op -eq 'write') { "pim.Settings '$Name' written (updated $($r.updated), inserted $($r.inserted)) and read back" } else { 'pim.Settings read' }) by the one-time job" 'Green'
            }
        } catch { $problems.Add("the step stopped: $(& $first $_)") }
    } finally {
        # ---- 5. the job is removed and read back -- in EVERY path
        if ($res.jobCreated) {
            $left = & $remove
            if (-not $left) { $res.jobRemoved = $true; & $say "removed: the one-time job '$JobName' (read back: it is gone)" }
            else { $problems.Add("the one-time job '$JobName' is STILL in resource group $ResourceGroup ($left). It carries the database administrator identity and does nothing until it is started; remove it: Azure portal > resource group $ResourceGroup > $JobName > Delete -- the next run of this step removes it first.") }
        }
    }
    return (& $finish)
}

function New-PimJobRenameSqlJobState {
    # The state behind ONE -Sql seam: how to reach the install, and the values of the last run (served once per name).
    param(
        [Parameter(Mandatory)][scriptblock]$Arm,
        [scriptblock]$Logs,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string]$SqlServer = '',
        [string]$SqlDatabase = '',
        [scriptblock]$Sleep,
        [int]$TimeoutSeconds = 600,
        [int]$PollSeconds = 10,
        [int]$LogWaitSeconds = 300,
        [int]$ReadBackTries = 30,
        [switch]$WhatIfOnly
    )
    $a = @{ Arm = $Arm; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; SqlServer = $SqlServer; SqlDatabase = $SqlDatabase
            TimeoutSeconds = $TimeoutSeconds; PollSeconds = $PollSeconds; LogWaitSeconds = $LogWaitSeconds; ReadBackTries = $ReadBackTries }
    if ($Logs) { $a['Logs'] = $Logs }
    if ($Sleep) { $a['Sleep'] = $Sleep }
    return @{ args = $a; whatIf = [bool]$WhatIfOnly; snapshot = $null; served = @{}; runs = ([System.Collections.Generic.List[object]]::new()) }
}

function Invoke-PimJobRenameSqlJobSeam {
    <#
      The -Sql seam of Rename-PimJobs.ps1 / Invoke-PimJobRename through the one-time job. 'get' -> the value ($null = no row);
      'set' -> $null. Throws on a refused name, in a preview (-WhatIfOnly: a preview creates no job) and when a run fails --
      the library then reports pim.Settings as not read, or stops the switch with its rollback.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][string]$Action, [AllowEmptyString()][string]$Name, [AllowNull()]$Value)
    if (-not (Test-PimJobRenameSqlJobSettingName -Name $Name)) { throw "refusing pim.Settings '$Name' (this step writes SchedulerTickJobId and InstallNames only)" }
    if ($Action -notin @('get', 'set')) { throw "the pim.Settings seam knows 'get' and 'set', not '$Action'" }
    if ($State.whatIf) { throw 'What if: pim.Settings is reached through a one-time job inside the install''s network, and a preview creates no job -- not read' }
    if ($Action -eq 'get' -and $null -ne $State.snapshot -and -not $State.served.ContainsKey($Name)) { $State.served[$Name] = $true; return $State.snapshot[$Name] }
    $a = $State.args.Clone()
    $op = if ($Action -eq 'get') { 'read' } else { 'write' }
    $r = Invoke-PimJobRenameSqlJob @a -Op $op -Name $Name -Value $Value
    $State.runs.Add($r)
    if (-not $r.ok) { $State.snapshot = $null; $State.served = @{}; throw "pim.Settings $(if ($op -eq 'write') { "'$Name' was not written" } else { 'was not read' }) through the one-time job: $(@($r.problems) -join '; ')" }
    $State.snapshot = $r.values; $State.served = @{}
    if ($Action -eq 'get') { $State.served[$Name] = $true; return $State.snapshot[$Name] }
    return $null
}
