#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.116, decision (31) -- "a job inside the install": the Invardia Support app's database user on an
  installation whose database is PRIVATE (public network access off), given by a one-time Container Apps job that runs
  INSIDE the installation's own environment. Shared by Invoke-PimSupportSqlAccessJob.ps1 and its offline test.

.DESCRIPTION
  A private database has no route from a setup machine, so Grant-PimSupportSqlAccess.ps1 stops there. Nothing is opened
  for this: no firewall rule, no public access, no jump host. The grant runs where the route already is.

  WHAT RUNS IN THE JOB is not a second implementation. The job's script is BUILT from the functions of
  _PimSupportSqlAccess.ps1 that are loaded in this process (their own text, taken with Get-Command): the SID from the
  client id, the statement (CREATE USER ... WITH SID, never FROM EXTERNAL PROVIDER; the role), the read, the read-back.
  One behaviour, whichever side runs it. The job needs nothing from the image but its token client and its SQL client
  (engine/_shared/PIM-Rest.ps1 + PIM-SqlStore.ps1 -- in every image that has the database setup job), so it works on an
  installation that is on an older version.

  WHICH IDENTITY. The installation already has one identity that may create a database user from inside: the
  user-assigned identity its database setup job (ca-pim-dbinit) signs in with -- the SQL server's administrator, or a
  member of the SQL admin group. The one-time job is given THAT identity (and the image-pull identity the setup job
  uses) and nothing else. No role, no group membership and no permission is given to any identity. When the
  installation has no such job, or its job does not name a user-assigned identity, or its image is pulled with the
  job's own system identity or a password, the run STOPS before anything is changed and says the options.

  Every caller hands in:
    -Arm   { param([string]$Method, [string]$Path, $Body) }   ARM, the path carries its api-version; throws "... HTTP <code> ..."
    -Graph { param([string]$Method, [string]$Path, $Body) }   Microsoft Graph v1.0 (one read: the Support app exists here)
    -Logs  { param([string]$WorkspaceId, [string]$Execution) } the console lines of one execution (Log Analytics); may return none
  Defaults are functions that return a literal (a $script: variable is $null in a child script scope).
  Needs _PimScriptDoc.ps1 and _PimSupportSqlAccess.ps1 loaded first.
#>

function Get-PimSupportSqlJobDefaultName { return 'caj-pim-supportsql' }
function Get-PimSupportSqlJobTemplateName { return 'ca-pim-dbinit' }
function Get-PimSupportSqlJobAcaApi { return '2024-03-01' }
function Get-PimSupportSqlJobTagName { return 'pim-one-time-job' }
function Get-PimSupportSqlJobTagValue { return 'support-sql-access' }
function Get-PimSupportSqlJobScriptName { return 'Invoke-PimSupportSqlAccessJob' }
function Get-PimSupportSqlJobDefaultAppRoot { return '/app/PIM4EntraPS' }
function Get-PimSupportSqlJobIdentitySetting { return 'PIM_DBINIT_MI_CLIENT_ID' }

function Get-PimSupportSqlJobFunctionNames {
    # PURE. The functions of _PimSupportSqlAccess.ps1 the job carries, in load order. Nothing else of that file runs inside.
    return @('Get-PimSupportSqlUserDefaultName', 'Get-PimSupportSqlRoleName', 'ConvertTo-PimSupportSqlSid', 'Test-PimSupportSqlNames',
             'Get-PimSupportSqlUserSql', 'Get-PimSupportSqlUserReadSql', 'ConvertFrom-PimSupportSqlUserRead', 'Invoke-PimSupportSqlUser')
}

function ConvertTo-PimSupportSqlJobMap {
    # PURE. A JSON object or a dictionary -> an ordered name -> value table (empty for nothing).
    param([AllowNull()]$Object)
    $o = [ordered]@{}
    if ($null -eq $Object) { return $o }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in @($Object.Keys)) { $o["$k"] = $Object[$k] }; return $o }
    foreach ($p in @($Object.PSObject.Properties)) { $o["$($p.Name)"] = $p.Value }
    return $o
}

function Get-PimSupportSqlJobScript {
    <#
      PURE (reads only the functions loaded in this process). The PowerShell the one-time job runs: the token client and
      the SQL client of the image, the grant functions of _PimSupportSqlAccess.ps1 word for word, one call of
      Invoke-PimSupportSqlUser as the identity named in PIM_SUPPORTSQL_MI_CLIENT_ID, and ONE result line
      "[supportsql] RESULT {json}". Exit 0 only when the user and its role were READ BACK.
      state: created | role-added | unchanged (one read, no statement sent) | failed.
    #>
    param([string]$AppRoot = (Get-PimSupportSqlJobDefaultAppRoot))
    $root = "$AppRoot".Trim().TrimEnd('/')
    if ($root -notmatch '^[A-Za-z0-9_./:~ -]+$') { throw "Get-PimSupportSqlJobScript: '$AppRoot' is not a safe folder path." }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('$ErrorActionPreference = ''Stop''')
    $l.Add('$rc = 1')
    $l.Add('function Write-SupportSqlLine { param([string]$Message) Write-Host (''[supportsql] '' + $Message) }')
    foreach ($n in @(Get-PimSupportSqlJobFunctionNames)) {
        $c = Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue
        if (-not $c) { throw "Get-PimSupportSqlJobScript: the function $n is not loaded (_PimSupportSqlAccess.ps1)." }
        $l.Add("function $n {")
        $l.Add("$($c.Definition)")
        $l.Add('}')
    }
    $main = @'
try {
    Write-SupportSqlLine 'start: the database user of the Invardia Support app (PIM Manager, one-time job)'
    . '__APPROOT__/engine/_shared/PIM-Rest.ps1'
    . '__APPROOT__/engine/_shared/PIM-SqlStore.ps1'
    $server = "$($env:PIM_SqlServer)".Trim()
    $database = "$($env:PIM_SqlDatabase)".Trim()
    if (-not $database) { $database = 'PimPlatform' }
    $appId = "$($env:PIM_SUPPORTSQL_APP_ID)".Trim()
    $userName = "$($env:PIM_SUPPORTSQL_DB_USER)".Trim()
    if (-not $userName) { $userName = Get-PimSupportSqlUserDefaultName }
    $miClientId = "$($env:PIM_SUPPORTSQL_MI_CLIENT_ID)".Trim()
    if (-not $server -or -not $appId -or -not $miClientId) { throw 'PIM_SqlServer, PIM_SUPPORTSQL_APP_ID and PIM_SUPPORTSQL_MI_CLIENT_ID must all be set -- nothing was changed' }
    $global:PIM_ManagedIdentityClientId = $miClientId
    $supportSql = @{ calls = 0; conn = "Server=tcp:$server,1433;Database=$database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60" }
    Write-SupportSqlLine "database $server / $database, signing in as the managed identity $miClientId"
    $sql = {
        param([string]$Query)
        $supportSql.calls++
        $c = New-PimSqlConnection -ConnectionString $supportSql.conn
        $c.Open()
        try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 120; return $cmd.ExecuteScalar() } finally { $c.Close() }
    }
    $u = Invoke-PimSupportSqlUser -Sql $sql -AppId $appId -DbUserName $userName
    $state = 'failed'
    if ($u.ok) { if ($u.created) { $state = 'created' } elseif ($supportSql.calls -gt 1) { $state = 'role-added' } else { $state = 'unchanged' } }
    $result = [ordered]@{ ok = [bool]$u.ok; state = $state; userName = "$($u.userName)"; role = "$($u.role)"; inRole = [bool]$u.inRole
                          sid = (ConvertTo-PimSupportSqlSid -AppId $appId); statements = [int]$supportSql.calls; problem = "$($u.problem)" }
    Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress))
    if ($u.ok) { $rc = 0 }
} catch {
    $m = (("$($_.Exception.Message)" -split "`n")[0]).Trim()
    $failed = [ordered]@{ ok = $false; state = 'failed'; userName = ''; role = ''; inRole = $false; sid = ''; statements = 0; problem = $m }
    Write-SupportSqlLine ('RESULT ' + ($failed | ConvertTo-Json -Compress))
}
exit $rc
'@
    $l.Add($main.Replace('__APPROOT__', $root))
    return ($l -join "`n")
}

function ConvertFrom-PimSupportSqlJobLog {
    # PURE. The console lines of the execution -> @{ lines (no blanks, no colour codes); result (the LAST RESULT line as an object, or $null) }.
    param([AllowNull()][string[]]$Lines)
    $out = New-Object System.Collections.Generic.List[string]
    $res = $null
    foreach ($x in @($Lines)) {
        $t = ("$x" -replace '\x1b\[[0-9;]*m', '').TrimEnd()
        if (-not $t.Trim()) { continue }
        $out.Add($t)
        if ($t -match '^\s*\[supportsql\] RESULT (\{.*\})\s*$') { try { $res = $Matches[1] | ConvertFrom-Json } catch { $res = $null } }
    }
    return @{ lines = @($out.ToArray()); result = $res }
}

function Get-PimSupportSqlJobLogQuery {
    # PURE. The Log Analytics query for the console lines of ONE execution, oldest first.
    param([Parameter(Mandatory)][string]$Execution, [int]$Take = 200)
    if ("$Execution" -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,80}$') { throw "Get-PimSupportSqlJobLogQuery: '$Execution' is not an execution name." }
    return "ContainerAppConsoleLogs_CL | where ContainerGroupName_s startswith '$Execution' | sort by TimeGenerated asc | take $([Math]::Max(1, $Take)) | project TimeGenerated, Log_s"
}

function Get-PimSupportSqlJobOptions {
    # PURE. What a person can do when the installation has no identity this script may use. Nothing here widens a right.
    param([string]$TemplateJobName = (Get-PimSupportSqlJobTemplateName))
    return @(
        "(a) run Grant-PimSupportSqlAccess.ps1 from a machine inside the PIM Manager network (a machine that reaches the SQL server's private endpoint) -- $(Get-PimScriptDocUrl -Script (Get-PimSupportSqlScriptName))",
        "(b) if another job of this installation carries the SQL admin identity as a user-assigned identity and pulls its image with a user-assigned identity, name it: -TemplateJobName <job> -SqlIdentityClientId <that identity's client id>",
        "(c) ask Invardia support: the installation's database setup job ($TemplateJobName) is what this script copies its identity from, and this installation does not have it in that form"
    )
}

function Get-PimSupportSqlJobCommand {
    # PURE. The two lines a person runs: the download, then the run (framework 12.10 item 11) -- parameters, never a file.
    param([string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup, [string]$SupportAppId)
    $name = Get-PimSupportSqlJobScriptName
    $run = ".\$name.ps1 -TenantId '$TenantId' -SubscriptionId '$SubscriptionId' -ResourceGroup '$ResourceGroup' -SupportAppId '$SupportAppId'"
    return @(Get-PimSupportScriptCommand -Script $name -Run @($run))
}

function Get-PimSupportSqlJobPlan {
    <#
      PURE. From the installation's own database setup job (-Template, the ARM object) to the one-time job: which
      identity, which database, which image, and the whole resource body. Never throws.
      Returns { ok; problem; identityResourceId; identityName; identityClientId; identitySource; pullIdentities;
                sqlServer; sqlDatabase; image; environmentId; location; appRoot; script; resource }.
      ok = $false + problem: the template cannot be used WITHOUT giving some identity a new right -- the caller stops.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Template,
        [Parameter(Mandatory)][string]$TemplateJobName,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$SupportAppId,
        [string]$DbUserName = (Get-PimSupportSqlUserDefaultName),
        [string]$SqlIdentityClientId = ''
    )
    $p = [ordered]@{ ok = $false; problem = ''; identityResourceId = ''; identityName = ''; identityClientId = ''; identitySource = ''; pullIdentities = @()
                     sqlServer = ''; sqlDatabase = ''; image = ''; environmentId = ''; location = ''; appRoot = ''; script = ''; resource = $null }
    try {
        if ("$JobName" -cnotmatch '^[a-z][a-z0-9-]{0,30}[a-z0-9]$') { $p.problem = "'$JobName' is not a job name (lower-case letters, digits and '-', at most 32 characters)"; return [pscustomobject]$p }
        if ("$JobName" -ieq "$TemplateJobName") { $p.problem = "the one-time job cannot have the name of the job it is copied from ('$TemplateJobName')"; return [pscustomobject]$p }
        [void](ConvertTo-PimSupportSqlSid -AppId $SupportAppId)
        Test-PimSupportSqlNames -DbUserName $DbUserName -Role (Get-PimSupportSqlRoleName)
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

        # ---- the identity: one the template job ALREADY carries, found by its client id. Never a new one.
        $setting = Get-PimSupportSqlJobIdentitySetting
        $cid = "$SqlIdentityClientId".Trim().ToLowerInvariant(); $src = 'named with -SqlIdentityClientId'
        if (-not $cid) { $cid = "$($envMap[$setting])".Trim().ToLowerInvariant(); $src = "the identity $TemplateJobName signs in to the database with (its setting $setting)" }
        $ua = ConvertTo-PimSupportSqlJobMap $(if ($Template.identity) { $Template.identity.userAssignedIdentities } else { $null })
        if ($cid -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
            $carried = @(@($ua.Keys) | ForEach-Object { "$(("$_" -split '/')[-1]) (client id $("$($ua[$_].clientId)".Trim()))" })
            $p.problem = "the job '$TemplateJobName' does not say which identity it signs in to the database with (no setting $setting), so there is no identity of this installation this script may use by itself. " +
                         $(if ($carried.Count) { "The user-assigned identities it carries: $($carried -join ', ') -- when one of them is the SQL server's administrator (or a member of the SQL admin group), name it with -SqlIdentityClientId <its client id>" } else { 'It carries no user-assigned identity at all' })
            return [pscustomobject]$p
        }
        $sqlKey = ''
        foreach ($k in @($ua.Keys)) { if ("$($ua[$k].clientId)".Trim().ToLowerInvariant() -eq $cid) { $sqlKey = "$k"; break } }
        if (-not $sqlKey) {
            $p.problem = "the identity $cid is not one of the user-assigned identities of the job '$TemplateJobName' -- this script never attaches an identity the installation's own job does not already carry"
            return [pscustomobject]$p
        }
        $p.identityResourceId = $sqlKey; $p.identityName = ($sqlKey -split '/')[-1]; $p.identityClientId = $cid; $p.identitySource = $src

        # ---- the image pull: only with a user-assigned identity the template job already carries
        $uaBody = [ordered]@{}; $uaBody[$sqlKey] = @{}
        $regs = New-Object System.Collections.Generic.List[object]
        $pull = New-Object System.Collections.Generic.List[string]
        foreach ($r in @(@($Template.properties.configuration.registries) | Where-Object { $_ })) {
            $server = "$($r.server)".Trim(); $ri = "$($r.identity)".Trim()
            if ("$($r.passwordSecretRef)".Trim() -or "$($r.username)".Trim()) {
                $p.problem = "the job '$TemplateJobName' pulls its image from $server with a user name and password -- a one-time job would need a copy of that password, and this script copies no secret"
                return [pscustomobject]$p
            }
            if (-not $ri -or $ri -ieq 'system') {
                $p.problem = "the job '$TemplateJobName' pulls its image from $server with its OWN system identity -- a new job has another identity, which would need a new right on the registry, and this script gives no identity a new right"
                return [pscustomobject]$p
            }
            $pk = ''
            foreach ($k in @($ua.Keys)) { if ("$k" -ieq $ri) { $pk = "$k"; break } }
            if (-not $pk) { $p.problem = "the job '$TemplateJobName' pulls its image from $server with an identity it does not carry ($ri)"; return [pscustomobject]$p }
            if (-not $uaBody.Contains($pk)) { $uaBody[$pk] = @{} }
            if ($pk -ine $sqlKey -and -not $pull.Contains($pk)) { $pull.Add($pk) }
            $regs.Add([ordered]@{ server = $server; identity = $pk })
        }
        $p.pullIdentities = @($pull.ToArray())

        # ---- where the image keeps the product: read off the template job's own start command
        $root = Get-PimSupportSqlJobDefaultAppRoot
        foreach ($a in @($c.args)) { if ("$a" -match '^(?<root>[A-Za-z0-9_./:~ -]+)/tools/pim-engine/[A-Za-z0-9_.-]+\.ps1$') { $root = $Matches['root']; break } }
        $p.appRoot = $root
        $p.script = Get-PimSupportSqlJobScript -AppRoot $root
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($p.script))

        $envList = @(
            @{ name = 'PIM_SqlServer'; value = $p.sqlServer }
            @{ name = 'PIM_SqlDatabase'; value = $p.sqlDatabase }
            @{ name = 'PIM_SUPPORTSQL_APP_ID'; value = "$SupportAppId".Trim().ToLowerInvariant() }
            @{ name = 'PIM_SUPPORTSQL_DB_USER'; value = "$DbUserName" }
            @{ name = 'PIM_SUPPORTSQL_MI_CLIENT_ID'; value = $cid }
        )
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
            env       = @($envList)
            resources = @{ cpu = 0.5; memory = '1.0Gi' }
        }) }
        $tags = @{}; $tags[(Get-PimSupportSqlJobTagName)] = (Get-PimSupportSqlJobTagValue)
        $p.resource = [ordered]@{ location = $p.location; tags = $tags; identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uaBody }; properties = $props }
        $p.ok = $true
    } catch { $p.ok = $false; $p.problem = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
    return [pscustomobject]$p
}

function Invoke-PimSupportSqlJobGrant {
    <#
      The one-time job, end to end (PIM REQUIREMENTS 100.116, decision 31):
        1. read the installation's database setup job; plan the one-time job from it (identity, database, image). No
           usable identity -> STOP with the options; nothing is changed
        2. read: is there already a job of the one-time name (a leftover of a killed run carries this script's tag; a
           job without the tag is NOT touched -> stop), and does the Support app exist in this tenant (Microsoft Graph)
        3. create the job (the tag, the identity the setup job already carries, the script) and wait until it is there
        4. start it, wait for the execution to end (bounded)
        5. read the execution's console lines from the environment's Log Analytics workspace (bounded; they arrive late)
        6. finally: remove the job and read back that it is gone -- also after a failed step
      PASS needs: the execution Succeeded (the job exits 0 only after it READ BACK the user and its role) and no result
      line that says otherwise. -WhatIfOnly: steps 1 and 2 are READ, the rest is printed. Nothing is written.
      Never throws. Returns { ok; exit (0 done, 1 not done); whatIf; plan; leftover; jobCreated; jobRemoved; execution;
      status; logLines; result; warnings; problems }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Arm,
        [scriptblock]$Graph,
        [scriptblock]$Logs,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SupportAppId,
        [string]$TemplateJobName = (Get-PimSupportSqlJobTemplateName),
        [string]$JobName = (Get-PimSupportSqlJobDefaultName),
        [string]$DbUserName = (Get-PimSupportSqlUserDefaultName),
        [string]$SqlIdentityClientId = '',
        [int]$TimeoutSeconds = 600,
        [int]$PollSeconds = 10,
        [int]$LogWaitSeconds = 180,
        [int]$ReadBackTries = 30,
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds },
        [switch]$WhatIfOnly
    )
    $api = Get-PimSupportSqlJobAcaApi
    $role = Get-PimSupportSqlRoleName
    $tagName = Get-PimSupportSqlJobTagName; $tagValue = Get-PimSupportSqlJobTagValue
    $rgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $jobPath = "$rgPath/providers/Microsoft.App/jobs/$JobName"
    $tplPath = "$rgPath/providers/Microsoft.App/jobs/$TemplateJobName"
    $notFound = '(?i)HTTP 404\b|ResourceNotFound|was not found|NotFound'
    $warnings = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    $res = [ordered]@{ ok = $false; exit = 1; whatIf = [bool]$WhatIfOnly; plan = $null; leftover = $false; jobCreated = $false; jobRemoved = $false
                       execution = ''; status = ''; logLines = @(); result = $null; warnings = @(); problems = @() }
    $say = { param([string]$m, [string]$c = 'Gray') Write-Host "  $m" -ForegroundColor $c }
    $first = { param($e) (("$($e.Exception.Message)" -split "`n")[0]).Trim() }
    $get = {
        param([string]$P)
        try { return (& $Arm 'GET' "${P}?api-version=$api" $null) }
        catch { if ("$($_.Exception.Message)" -match $notFound) { return $null }; throw }
    }
    $finish = {
        $res.warnings = @($warnings.ToArray()); $res.problems = @($problems.ToArray())
        $res.exit = if ($problems.Count) { 1 } else { 0 }
        $res.ok = ($res.exit -eq 0)
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
    $options = "Options:`n    " + (@(Get-PimSupportSqlJobOptions -TemplateJobName $TemplateJobName) -join "`n    ")

    # ---- 1. the installation's own database setup job, and the plan --------------------------------------------------
    $tpl = $null
    try { $tpl = & $get $tplPath }
    catch { $problems.Add("the job '$TemplateJobName' could not be read in resource group '$ResourceGroup': $(& $first $_) -- nothing was changed"); return (& $finish) }
    if (-not $tpl) {
        $problems.Add("this installation has no job '$TemplateJobName' in resource group '$ResourceGroup' (subscription $SubscriptionId). That job is where an installation with a private database keeps the identity that may create a database user from inside; without it this script has no identity it may use, and it gives no identity a new right. Nothing was changed.`n  $options")
        return (& $finish)
    }
    $plan = Get-PimSupportSqlJobPlan -Template $tpl -TemplateJobName $TemplateJobName -JobName $JobName -SupportAppId $SupportAppId -DbUserName $DbUserName -SqlIdentityClientId $SqlIdentityClientId
    $res.plan = $plan
    if (-not $plan.ok) { $problems.Add("$($plan.problem). Nothing was changed.`n  $options"); return (& $finish) }
    $sid = ConvertTo-PimSupportSqlSid -AppId $SupportAppId
    & $say "database: $($plan.sqlServer) / $($plan.sqlDatabase) (read from the job $TemplateJobName)"
    & $say "identity: $($plan.identityName) (client id $($plan.identityClientId)) -- $($plan.identitySource). It is used as it is: no role, no group membership and no permission is given to any identity."
    if (@($plan.pullIdentities).Count) { & $say "image pull: $((@($plan.pullIdentities) | ForEach-Object { ($_ -split '/')[-1] }) -join ', ') (the identity $TemplateJobName pulls its image with)" }
    & $say "image: $($plan.image) (the image of $TemplateJobName); environment: $(($plan.environmentId -split '/')[-1])"

    # ---- 2. what is there: a job of the one-time name, the Support app ------------------------------------------------
    try {
        $old = & $get $jobPath
        if ($old) {
            $tags = ConvertTo-PimSupportSqlJobMap $old.tags
            if ("$($tags[$tagName])" -ne $tagValue) {
                $problems.Add("a job named '$JobName' is already in resource group '$ResourceGroup' and was not made by this script (it does not carry the tag $tagName = $tagValue) -- it is not touched. Run again with -JobName <another name>. Nothing was changed.")
                return (& $finish)
            }
            $res.leftover = $true
        }
    } catch { $problems.Add("could not read whether a job '$JobName' is already there: $(& $first $_) -- nothing was changed"); return (& $finish) }
    if ($Graph) {
        try {
            $f = [uri]::EscapeDataString("appId eq '$("$SupportAppId".Trim())'")
            $sp = @((& $Graph 'GET' "/servicePrincipals?`$select=id,appId,displayName&`$filter=$f" $null).value | Where-Object { $_ }) | Select-Object -First 1
            if (-not $sp -or -not "$($sp.id)".Trim()) {
                $problems.Add("the application $SupportAppId has no service principal in this tenant -- create the Invardia Support app in this tenant first, or check the id. Nothing was changed.")
                return (& $finish)
            }
            & $say "Invardia Support app: '$($sp.displayName)' ($SupportAppId) exists in this tenant"
        } catch { $problems.Add("the Invardia Support app could not be looked up in this tenant (Microsoft Graph): $(& $first $_) -- a database owner is not created for an id that could not be checked. Nothing was changed."); return (& $finish) }
    }

    if ($WhatIfOnly) {
        if ($res.leftover) { Write-Host "What if: remove the job '$JobName' a killed run of this script left behind (it carries the tag $tagName = $tagValue)" }
        Write-Host "What if: create the one-time job '$JobName' in the environment $(($plan.environmentId -split '/')[-1]), running as $($plan.identityName), with the tag $tagName = $tagValue"
        Write-Host "What if: start it once. In the database $($plan.sqlDatabase) it creates the user [$DbUserName] from the Support app's client id (SID $sid) when no user has that id, and adds it to $role; an existing user of the Support app is reused whatever its name, and nothing is sent when it is already in $role"
        Write-Host "What if: read the execution's result and its log lines, then remove the job '$JobName' and read back that it is gone"
        Write-Host 'What if: the script the job would run (built from the same functions Grant-PimSupportSqlAccess.ps1 uses):'
        foreach ($line in @($plan.script -split "`n")) { Write-Host "    | $($line.TrimEnd())" }
        return (& $finish)
    }

    # ---- a leftover of a killed run goes first (its tag says it is this script's) --------------------------------------
    if ($res.leftover) {
        $left = & $remove
        if ($left) { $problems.Add("the job '$JobName' a killed run left behind could not be removed ($left) -- nothing else was changed. Remove it: Azure portal > resource group $ResourceGroup > $JobName > Delete, then run this script again."); return (& $finish) }
        & $say "removed: the job '$JobName' a killed run of this script left behind (read back)" 'Yellow'
    }

    $final = @('Succeeded', 'Failed', 'Degraded', 'Stopped')
    try {
        try {
            # ---- 3. create the job
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
            & $say "created: the one-time job '$JobName' (running as $($plan.identityName); removed again at the end)" 'Yellow'

            # ---- 4. start it once and wait
            $started = & $Arm 'POST' "${jobPath}/start?api-version=$api" @{}
            $exec = if ($started) { "$($started.name)".Trim() } else { '' }
            if (-not $exec) { throw "the job '$JobName' did not start (no execution was returned)" }
            $res.execution = $exec
            & $say "started: execution $exec -- waiting (at most $TimeoutSeconds seconds)"
            $tries = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSeconds / [double][Math]::Max(1, $PollSeconds)))
            $status = ''; $lastErr = ''
            for ($i = 0; $i -lt $tries; $i++) {
                & $Sleep $PollSeconds
                try { $x = & $get "$jobPath/executions/$exec"; $status = if ($x) { "$($x.properties.status)".Trim() } else { '' } } catch { $lastErr = & $first $_ }
                if ($status -in $final) { break }
            }
            $res.status = $status

            # ---- 5. the console lines (they reach the workspace late; a missing log never turns a result around)
            $lines = @()
            if ($Logs -and $status -in $final) {
                $ws = ''
                try { $envObj = & $get $plan.environmentId; if ($envObj) { $ws = "$($envObj.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim() } } catch { $ws = '' }
                if ($ws) {
                    $ltries = [Math]::Max(1, [int][Math]::Ceiling($LogWaitSeconds / 20.0))
                    $refused = 0
                    for ($i = 0; $i -lt $ltries; $i++) {
                        try { $lines = @(& $Logs $ws $exec | ForEach-Object { "$_" }); $refused = 0 } catch { $lines = @(); $refused++ }
                        if (@($lines | Where-Object { $_ -match '\[supportsql\] RESULT ' }).Count) { break }
                        if ($refused -ge 2) { break }     # a read that is refused twice in a row (no reader right) is not asked again
                        if ($i -lt $ltries - 1) { & $Sleep 20 }
                    }
                }
            }
            $log = ConvertFrom-PimSupportSqlJobLog -Lines $lines
            $res.logLines = @($log.lines); $res.result = $log.result
            if (@($log.lines).Count) { & $say "the job's log ($(@($log.lines).Count) line(s)):"; foreach ($ln in @($log.lines)) { Write-Host "    | $ln" -ForegroundColor DarkGray } }
            else { & $say "the job's log could not be read (it reaches the environment's Log Analytics workspace a few minutes after the run: ContainerAppConsoleLogs_CL, ContainerGroupName_s startswith '$exec')" 'DarkGray' }

            # ---- the verdict
            $r = $log.result
            if ($status -eq 'Succeeded' -and $r -and -not [bool]$r.ok) {
                $problems.Add("the execution $exec ended Succeeded but its result line says it did not put the user in place ($($r.problem)) -- treated as NOT done")
            } elseif ($status -eq 'Succeeded') {
                if ($r) {
                    $what = switch ("$($r.state)") { 'created' { 'created' } 'role-added' { "was there, added to $role" } 'unchanged' { 'was already there -- nothing was changed in the database' } default { 'in place' } }
                    & $say "database user [$($r.userName)] (the Support app's client id, SID $sid): $what; member of $role (read back by the job)" 'Green'
                } else {
                    $warnings.Add("the execution $exec ended Succeeded, and the job ends that way only after it read the user and its role back; its log lines could not be read here, so the user's name and whether it was created or already there are not shown")
                }
            } elseif ($status -in $final) {
                $problems.Add("the one-time job ended '$status' (execution $exec)$(if ($r -and "$($r.problem)") { ": $($r.problem)" } elseif (-not @($log.lines).Count) { ' and wrote no log line this run could read -- when the image could not be pulled or the job could not start, there is none' }). The database user was NOT confirmed.")
            } else {
                $problems.Add("the one-time job did not end within $TimeoutSeconds seconds (execution $exec, last state '$status'$(if ($lastErr) { ", last read: $lastErr" })). The database user was NOT confirmed.")
                try { [void](& $Arm 'POST' "${jobPath}/executions/$exec/stop?api-version=$api" @{}) } catch { }
            }
        } catch { $problems.Add("the step stopped: $(& $first $_)") }
    } finally {
        # ---- 6. the job is removed and read back -- also after a failed step
        if ($res.jobCreated) {
            $left = & $remove
            if (-not $left) { $res.jobRemoved = $true; & $say "removed: the one-time job '$JobName' (read back: it is gone)" 'Green' }
            else { $problems.Add("the one-time job '$JobName' is STILL in resource group $ResourceGroup ($left). It carries the SQL admin identity and does nothing until it is started; remove it: Azure portal > resource group $ResourceGroup > $JobName > Delete -- or run this script again, which removes it first.") }
        }
    }
    return (& $finish)
}
