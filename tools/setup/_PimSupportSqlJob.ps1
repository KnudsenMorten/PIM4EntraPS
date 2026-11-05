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

  TIME-LIMITED ACCESS (framework SECAUDIT-1a 4b / 4c, PIM SEC-92): in mode grant the job gives the admin role only until
  that time, records the end on the database user (the marker of engine/_shared/PIM-SupportJit.ps1), keeps running, and
  takes the admin role back at that time ON ITS OWN -- no answer from Invardia, no person and no other job is needed for
  the access to end. Every run of the job first SWEEPS: any grant whose end has passed is taken back before anything is
  given. In mode standing (OPEN-01) the job gives the STANDING READ-ONLY access only: the support access step
  (Invoke-PimSupportSqlReadOnlyUser) with the user in pim_support_read -- never db_owner, never the SQL admin group; a
  db_owner an earlier version gave is reported in the result line (legacyOwner), never kept as "in place".
#>
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SupportJit.ps1')    # the marker, the grant, the revoke and the sweep

function Get-PimSupportSqlJobDefaultName { return 'caj-pim-supportsql' }
function Get-PimSupportSqlJobTemplateName { return 'ca-pim-dbinit' }
function Get-PimSupportSqlJobAcaApi { return '2024-03-01' }
function Get-PimSupportSqlJobTagName { return 'pim-one-time-job' }
function Get-PimSupportSqlJobTagValue { return 'support-sql-access' }
function Get-PimSupportSqlJobScriptName { return 'Invoke-PimSupportSqlAccessJob' }
function Get-PimSupportSqlJobDefaultAppRoot { return '/app/PIM4EntraPS' }
function Get-PimSupportSqlJobIdentitySetting { return 'PIM_DBINIT_MI_CLIENT_ID' }
function Get-PimSupportSqlJobUntilTagName { return 'pim-support-until' }

function Get-PimSupportSqlJobFunctionNames {
    # PURE. The functions the job carries, in load order: those of _PimSupportSqlAccess.ps1 (the standing grant) and those
    # of engine/_shared/PIM-SupportJit.ps1 (the time-limited grant, the revoke and the sweep). Nothing else runs inside.
    return @('Get-PimSupportSqlUserDefaultName', 'Get-PimSupportSqlRoleName', 'Get-PimSupportSqlLegacyRoleNames', 'ConvertTo-PimSupportSqlSid', 'Test-PimSupportSqlNames',
             'Get-PimSupportSqlUserSql', 'Get-PimSupportSqlUserReadSql', 'ConvertFrom-PimSupportSqlUserRead', 'Invoke-PimSupportSqlUser', 'Invoke-PimSupportSqlReadOnlyUser',
             'Get-PimSupportJitSchemaName', 'Get-PimSupportJitVersionMark', 'Get-PimSupportJitSignerPrefix', 'Get-PimSupportJitProcedureNames',
             'Get-PimSupportJitAdminRole', 'Get-PimSupportJitReadOnlyRole', 'Get-PimSupportJitReadSchemas', 'Get-PimSupportJitLegacyReadOnlyRole', 'Get-PimSupportJitDefaultHours', 'Get-PimSupportJitMaxHours',
             'Get-PimSupportJitNotSetUpText', 'Get-PimSupportJitLevels', 'ConvertTo-PimSupportJitLevel', 'Get-PimSupportJitLowerLevel', 'Test-PimSupportJitUserName', 'ConvertTo-PimSupportJitText',
             'Format-PimSupportJitUtc', 'ConvertFrom-PimSupportJitUtc', 'ConvertTo-PimSupportJitSqlText', 'Get-PimSupportJitTableSql', 'Get-PimSupportJitReadRoleSql',
             'Get-PimSupportJitProcedureText', 'Get-PimSupportJitInstallBatches', 'Get-PimSupportJitInstallFactsSql', 'ConvertFrom-PimSupportJitAnswer',
             'Get-PimSupportJitFirstLine', 'Test-PimSupportJitNotInstalled', 'Invoke-PimSupportJitGrant', 'Invoke-PimSupportJitRevoke',
             'Invoke-PimSupportJitSweep', 'Get-PimSupportJitState', 'Get-PimSupportJitStateSummary', 'Test-PimSupportJitNeedsLook', 'Invoke-PimSupportJitInstall')
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
      state (standing): created | in-place | failed.
      PIM_SUPPORTSQL_MODE (framework SECAUDIT-1a 4b / 4c; engine/_shared/PIM-SupportJit.ps1):
        standing (default)  OPEN-01: the STANDING READ-ONLY user (Invoke-PimSupportSqlReadOnlyUser; consent
                            PIM_SUPPORTSQL_CONSENT_LEVEL troubleshoot | setup, '' = as recorded, else troubleshoot) --
                            never db_owner; an earlier db_owner is reported (legacyOwner), never "in place"
        install             THE SUPPORT-SESSION STEP: consent (PIM_SUPPORTSQL_CONSENT_LEVEL), the read-only user, the
                            signed procedures; read back. Needs an owner-level identity (the database setup job's).
        grant               4b: usp_SupportGrant (PIM_SUPPORTSQL_JIT_LEVEL / _HOURS / _REASON / _TICKET / _OPENED_BY); for an
                            owner grant the job stays, follows the end (a re-open moves it later) and at the end SWEEPS
                            ("[supportsql] REVOKE {json}") -- never before the end. Exit 0 only when that sweep is clean.
        close               support closed: every open marker closed now (only roles the grant added), sessions ended
        consent             OPEN-01: ONE action the UPDATER decided from Invardia's consent channel
                            (PIM_SUPPORTSQL_CONSENT_ACTION ensure-read-user | remove-user | open-admin | close-admin,
                            PIM_SUPPORTSQL_CONSENT_LEVEL troubleshoot | setup | none, PIM_SUPPORTSQL_JIT_UNTIL for open-admin).
                            The support-session step with Invardia's consent first (idempotent: objects current + signed,
                            the read role, the consent row, the read user -- or for none every grant closed and the user
                            removed), then the open / close, then the state READ BACK. Exit 0 only when it reads back as asked.
      Every mode but install first SWEEPS ("[supportsql] SWEEP {json}"); every open / close / revoke is audited
      ("[supportsql] AUDIT {json}" + a row in the audit table when the image has the writer).
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
    # every grant and every revoke is audited: a log line always, and a row in the audit table when the image has the writer
    $jobAudit = {
        param($Record)
        Write-SupportSqlLine ('AUDIT ' + ($Record | ConvertTo-Json -Compress))
        if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimSqlAuditEvent -ConnectionString $supportSql.conn -Actor 'job:support-access' -ActorSource 'job' -Action "$($Record.action)" -Target "$($Record.target)" -After $Record -Result "$($Record.result)"
        }
    }
    $sweepLine = {
        param($S)
        [ordered]@{ ok = [bool]$S.ok; installed = $S.installed; found = [int]$S.found; revoked = @($S.revoked).Count; failed = @($S.failed).Count
                    sessionsEnded = [int]$S.sessionsEnded; jitOpen = $S.jitOpen; jitUntil = "$($S.jitUntil)"; problems = @($S.problems) }
    }
    $mode = "$($env:PIM_SUPPORTSQL_MODE)".Trim().ToLowerInvariant()
    if (-not $mode) { $mode = 'standing' }
    if ($mode -notin @('standing', 'install', 'grant', 'close', 'consent')) { throw "PIM_SUPPORTSQL_MODE '$mode' is not standing, install, grant, close or consent -- nothing was changed" }
    $sweepBad = $false; $sw0Line = $null
    if ($mode -ne 'install') {
        # ---- the sweep FIRST (framework SECAUDIT-1a 4c): every marker past its end is taken back before anything is given
        $sw0 = Invoke-PimSupportJitSweep -Sql $sql -Source 'job' -Audit $jobAudit -Quiet
        $sw0Line = & $sweepLine $sw0
        Write-SupportSqlLine ('SWEEP ' + ($sw0Line | ConvertTo-Json -Compress))
        if ($sw0.installed -eq $false) { Write-SupportSqlLine (Get-PimSupportJitNotSetUpText) }
        $sweepBad = [bool](-not $sw0.ok)
        $supportSql.calls = 0
    }
    if ($mode -eq 'install') {
        # ---- THE SUPPORT-SESSION STEP (4c): consent, the standing read-only user, the signed procedures. Owner-level identity.
        $consent = "$($env:PIM_SUPPORTSQL_CONSENT_LEVEL)".Trim().ToLowerInvariant()
        $i = Invoke-PimSupportJitInstall -Sql $sql -SupportAppId $appId -ConsentLevel $consent -UserName $userName -SetBy "$($env:PIM_SUPPORTSQL_JIT_OPENED_BY)"
        try { & $jobAudit ([pscustomobject][ordered]@{ action = 'support.access.install'; target = 'the support access procedures'; source = 'job'; consented = "$($i.consented)"; result = $(if ($i.ok) { 'ok' } else { 'failed' }); detail = (@($i.problems) -join '; ') }) }
        catch { Write-SupportSqlLine ('WARNING the audit record of the installation could not be written: ' + ((("$($_.Exception.Message)" -split "`n")[0]).Trim())) }
        $result = [ordered]@{ ok = [bool]$i.ok; state = $(if ($i.ok) { 'installed' } else { 'failed' }); mode = 'install'; consented = "$($i.consented)"; userName = $userName
                              procedures = @($i.procedures); problem = (@($i.problems) -join '; ') }
        Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        if ($i.ok) { $rc = 0 }
    } elseif ($mode -eq 'consent') {
        # ---- OPEN-01: ONE action the UPDATER decided from Invardia's consent channel (framework "SUPPORT ACCESS" point 2)
        $action = "$($env:PIM_SUPPORTSQL_CONSENT_ACTION)".Trim().ToLowerInvariant()
        $consent = ConvertTo-PimSupportJitLevel "$($env:PIM_SUPPORTSQL_CONSENT_LEVEL)"
        if ($action -notin @('ensure-read-user', 'remove-user', 'open-admin', 'close-admin')) { throw "PIM_SUPPORTSQL_CONSENT_ACTION '$action' is not ensure-read-user, remove-user, open-admin or close-admin -- nothing was changed" }
        if (-not $consent) { throw "PIM_SUPPORTSQL_CONSENT_LEVEL '$($env:PIM_SUPPORTSQL_CONSENT_LEVEL)' is not troubleshoot, setup or none -- nothing was changed" }
        if ($action -eq 'remove-user') { $consent = 'none' }
        if ($action -eq 'open-admin' -and $consent -ne 'setup') { throw "open-admin needs the consent level setup (Invardia says '$consent') -- nothing was given" }
        $cp = New-Object System.Collections.Generic.List[string]
        # 1. the support-session step with Invardia's consent (idempotent; for none: every grant closed, the user removed)
        $i = Invoke-PimSupportJitInstall -Sql $sql -SupportAppId $appId -ConsentLevel $consent -UserName $userName -SetBy "$($env:PIM_SUPPORTSQL_JIT_OPENED_BY)"
        foreach ($ip in @($i.problems)) { $cp.Add("$ip") }
        $g = $null; $cl = $null
        # 2. the open (setup inside an open support session) or the close
        if ($action -eq 'open-admin' -and $i.ok) {
            $g = Invoke-PimSupportJitGrant -Sql $sql -Level 'setup' -Hours (Get-PimSupportJitMaxHours) -UntilUtc "$($env:PIM_SUPPORTSQL_JIT_UNTIL)" -Reason "$($env:PIM_SUPPORTSQL_JIT_REASON)" -Ticket "$($env:PIM_SUPPORTSQL_JIT_TICKET)" -OpenedBy "$($env:PIM_SUPPORTSQL_JIT_OPENED_BY)"
            if (-not $g.ok) { $cp.Add("the open: $($g.problem)") }
            try { & $jobAudit ([pscustomobject][ordered]@{ action = 'support.access.open'; target = 'the Support app''s database user'; source = 'job:consent'; level = "$($g.level)"; requested = 'setup'; consented = "$($g.consented)"
                                                             grantId = "$($g.grantId)"; untilUtc = "$($g.untilUtc)"; result = $(if ($g.ok) { 'ok' } else { 'failed' }); detail = "$($g.problem)" }) }
            catch { Write-SupportSqlLine ('WARNING the audit record of the open could not be written: ' + ((("$($_.Exception.Message)" -split "`n")[0]).Trim())) }
        } elseif ($action -eq 'close-admin') {
            $cl = Invoke-PimSupportJitRevoke -Sql $sql -Mode 'all' -Source 'job' -Audit $jobAudit -Quiet
            foreach ($cq in @($cl.problems)) { $cp.Add("the close: $cq") }
        }
        try { & $jobAudit ([pscustomobject][ordered]@{ action = 'support.consent.apply'; target = 'the Support app''s database access'; source = 'job:consent'; consentAction = $action; consented = $consent
                                                         result = $(if ($cp.Count) { 'failed' } else { 'ok' }); detail = (@($cp.ToArray()) -join '; ') }) }
        catch { Write-SupportSqlLine ('WARNING the audit record of the consent could not be written: ' + ((("$($_.Exception.Message)" -split "`n")[0]).Trim())) }
        # 3. READ BACK: the state as the action asked for it
        $st = Get-PimSupportJitState -Sql $sql
        if (-not $st.read) { $cp.Add("the state could not be read back ($($st.problem))") }
        else {
            switch ($action) {
                'ensure-read-user' { if (-not $st.readOnly) { $cp.Add('read-back: the Support app''s user is not in the read role') } }
                'remove-user'      { if ($st.userExists -ne $false) { $cp.Add('read-back: the Support app''s database user is still there') } }
                'open-admin'       { if (-not ($st.inOwner -and $st.jitOpen)) { $cp.Add('read-back: no open admin access') } }
                'close-admin'      { if ($st.jitOpen) { $cp.Add('read-back: an admin access is still open') } }
            }
        }
        if ($sweepBad) { $cp.Add("the sweep before the action: $(@($sw0.problems) -join '; ')") }
        $result = [ordered]@{ ok = [bool](-not $cp.Count); state = $action; mode = 'consent'; action = $action; consented = "$($st.consented)"; userExists = $st.userExists; readOnly = $st.readOnly
                              inOwner = $st.inOwner; jitOpen = $st.jitOpen; jitUntil = "$($st.jitUntil)"; userName = $userName; problem = (@($cp.ToArray()) -join '; '); sweep = $sw0Line }
        Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        if ($result.ok) { $rc = 0 }
    } elseif ($mode -eq 'close') {
        # ---- support closed: every open marker is closed now (only roles the grant added), then the sessions end
        $cl = Invoke-PimSupportJitRevoke -Sql $sql -Mode 'all' -Source 'job' -Audit $jobAudit -Quiet
        $result = [ordered]@{ ok = [bool]($cl.ok -and -not $sweepBad); state = $(if ($cl.installed -eq $false) { 'not-installed' } elseif ($cl.ok) { 'closed' } else { 'failed' }); mode = 'close'
                              closed = @($cl.revoked).Count; failed = @($cl.failed).Count; sessionsEnded = [int]$cl.sessionsEnded; problem = (@(@($sw0.problems) + @($cl.problems)) -join '; '); sweep = $sw0Line }
        Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        if ($result.ok) { $rc = 0 }
    } elseif ($mode -eq 'grant') {
        # ---- 4b: the grant through the SIGNED procedure (the level = the LOWER of requested and consented), read back
        $hours = 0; [void][int]::TryParse("$($env:PIM_SUPPORTSQL_JIT_HOURS)".Trim(), [ref]$hours)
        $level = "$($env:PIM_SUPPORTSQL_JIT_LEVEL)".Trim().ToLowerInvariant(); if (-not $level) { $level = 'setup' }
        $level = ConvertTo-PimSupportJitLevel $level     # v1 read / owner -> troubleshoot / setup (never widened)
        if ($level -notin @('troubleshoot', 'setup')) { throw "PIM_SUPPORTSQL_JIT_LEVEL '$($env:PIM_SUPPORTSQL_JIT_LEVEL)' is not troubleshoot or setup -- nothing was given" }
        $g = Invoke-PimSupportJitGrant -Sql $sql -Level $level -Hours $hours -Reason "$($env:PIM_SUPPORTSQL_JIT_REASON)" -Ticket "$($env:PIM_SUPPORTSQL_JIT_TICKET)" -OpenedBy "$($env:PIM_SUPPORTSQL_JIT_OPENED_BY)"
        try { & $jobAudit ([pscustomobject][ordered]@{ action = 'support.access.open'; target = 'the Support app''s database user'; source = 'job'; level = "$($g.level)"; requested = "$($g.requested)"; consented = "$($g.consented)"
                                                         grantId = "$($g.grantId)"; untilUtc = "$($g.untilUtc)"; result = $(if ($g.ok) { 'ok' } else { 'failed' }); detail = "$($g.problem)" }) }
        catch { Write-SupportSqlLine ('WARNING the audit record of the grant could not be written: ' + ((("$($_.Exception.Message)" -split "`n")[0]).Trim())) }
        $problem = "$($g.problem)"; if (-not $problem -and $sweepBad) { $problem = "the sweep before the grant: $(@($sw0.problems) -join '; ')" }
        $result = [ordered]@{ ok = [bool]($g.ok -and -not $sweepBad); state = $(if (-not $g.ok) { 'failed' } elseif ($g.extended) { 'extended' } elseif ($g.level -eq 'setup' -and $g.preExisting) { 'pre-existing' } elseif ($g.level -eq 'setup') { 'granted' } else { 'read-only' })
                              mode = 'grant'; level = "$($g.level)"; requested = "$($g.requested)"; consented = "$($g.consented)"; grantId = "$($g.grantId)"; untilUtc = "$($g.untilUtc)"
                              role = (Get-PimSupportJitAdminRole); inRole = [bool]$g.inOwner; readOnly = [bool]$g.readOnly; installed = [bool]$g.installed; problem = $problem; sweep = $sw0Line }
        Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        if ($g.ok -and $g.level -eq 'setup' -and $g.untilUtc) {
            # ---- hold until the end, then SWEEP on this job's OWN schedule: no answer from Invardia, no person and no other
            # job is needed for the access to end. Never before the end; a later end (a re-open) is followed.
            $end = ConvertFrom-PimSupportJitUtc "$($g.untilUtc)"
            Write-SupportSqlLine "WAIT the admin access ends at $(Format-PimSupportJitUtc -Utc $end); this job takes it back then"
            while ($true) {
                $nowW = [datetime]::UtcNow
                $st = Get-PimSupportJitState -Sql $sql
                if ($st.read) {
                    if (-not $st.jitOpen) { Write-SupportSqlLine 'WAIT the admin access was already closed'; break }
                    $u2 = ConvertFrom-PimSupportJitUtc "$($st.jitUntil)"
                    if ($u2 -and $u2 -gt $end) { $end = $u2; Write-SupportSqlLine "WAIT the end was moved to $(Format-PimSupportJitUtc -Utc $end) (the support access was opened again)" }
                } else { Write-SupportSqlLine "WAIT the support access could not be read ($($st.problem)) -- read again" }
                # one second past the end: the stored end has whole seconds, the clock does not -- the sweep must find it due
                if ($nowW -ge $end.AddSeconds(1)) { break }
                Start-Sleep -Seconds ([int][Math]::Max(1, [Math]::Min(300, [Math]::Ceiling(($end.AddSeconds(1) - $nowW).TotalSeconds))))
            }
            $sw1 = Invoke-PimSupportJitSweep -Sql $sql -Source 'job' -Audit $jobAudit -Quiet
            $sw1Line = & $sweepLine $sw1
            Write-SupportSqlLine ('REVOKE ' + ($sw1Line | ConvertTo-Json -Compress))
            if ($sw1.ok) { $rc = 0 }
        } elseif ($result.ok) { $rc = 0 }
    } else {
        # ---- OPEN-01: the STANDING READ-ONLY user (the support access step) -- never db_owner, never the SQL admin group.
        # A db_owner an earlier version gave is REPORTED (legacyOwner), never counted as "in place" and never removed here.
        $consent = "$($env:PIM_SUPPORTSQL_CONSENT_LEVEL)".Trim().ToLowerInvariant()
        if ($consent -and $consent -notin @('troubleshoot', 'setup')) { throw "PIM_SUPPORTSQL_CONSENT_LEVEL '$consent' is not troubleshoot or setup -- nothing was changed" }
        $u = Invoke-PimSupportSqlReadOnlyUser -Sql $sql -AppId $appId -DbUserName $userName -ConsentLevel $consent -SetBy "$($env:PIM_SUPPORTSQL_JIT_OPENED_BY)"
        $state = 'failed'
        if ($u.ok) { if ($u.created) { $state = 'created' } else { $state = 'in-place' } }
        $problem = "$($u.problem)"; if (-not $problem -and $sweepBad) { $problem = "the sweep before the grant: $(@($sw0.problems) -join '; ')" }
        $result = [ordered]@{ ok = [bool]($u.ok -and -not $sweepBad); state = $state; userName = "$($u.userName)"; role = "$($u.role)"; inRole = [bool]$u.inRole
                              consented = "$($u.consented)"; legacy = @($u.legacy); legacyOwner = [bool]$u.legacyOwner; sessionOpen = [bool]$u.sessionOpen
                              sid = (ConvertTo-PimSupportSqlSid -AppId $appId); statements = [int]$supportSql.calls; problem = $problem; sweep = $sw0Line }
        Write-SupportSqlLine ('RESULT ' + ($result | ConvertTo-Json -Compress -Depth 4))
        if ($result.ok) { $rc = 0 }
    }
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

function ConvertTo-PimSupportSqlJobCommand {
    <#
      PURE. The job's -EncodedCommand: a SMALL bootstrap that un-gzips the script and runs it. The script itself (the
      standing grant, the signed-procedure install and the time-limited functions, word for word) is larger than one
      container argument may be once it is UTF-16 + base64 (Linux: 131072 bytes per argument); gzipped it is a fraction.
      The script still ends with "exit $rc", which ends the process with that code.
    #>
    param([Parameter(Mandatory)][string]$Script)
    $raw = [Text.Encoding]::UTF8.GetBytes($Script)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($raw, 0, $raw.Length); $gz.Close()
    $packed = [Convert]::ToBase64String($ms.ToArray())
    $boot = "`$b = [Convert]::FromBase64String('$packed'); `$m = New-Object System.IO.MemoryStream(,`$b); `$z = New-Object System.IO.Compression.GZipStream(`$m, [System.IO.Compression.CompressionMode]::Decompress); `$r = New-Object System.IO.StreamReader(`$z, [Text.Encoding]::UTF8); `$s = `$r.ReadToEnd(); `$r.Close(); . ([scriptblock]::Create(`$s))"
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($boot))
}

function ConvertFrom-PimSupportSqlJobCommand {
    # PURE. The script inside a job's -EncodedCommand (the bootstrap of ConvertTo-PimSupportSqlJobCommand), or '' when it is not one.
    param([AllowNull()][string]$Encoded)
    try {
        $boot = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("$Encoded"))
        if ($boot -notmatch "FromBase64String\('([A-Za-z0-9+/=]+)'\)") { return '' }
        $ms = New-Object System.IO.MemoryStream(, [Convert]::FromBase64String($Matches[1]))
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $sr = New-Object System.IO.StreamReader($gz, [Text.Encoding]::UTF8)
        $s = $sr.ReadToEnd(); $sr.Close()
        return $s
    } catch { return '' }
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
    # PowerShell 7's ConvertFrom-Json turns an ISO date string into a [datetime], which then prints in the LOCAL format
    # ("11/01/2026 18:00:00") -- the end time must stay the exact UTC text the job wrote (2026-11-02, release 3.0.17 gate).
    if ($res) {
        foreach ($p in @($res.PSObject.Properties)) {
            if ($p.Value -is [datetime]) { $p.Value = $p.Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
        }
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
        [string]$SqlIdentityClientId = '',
        # framework SECAUDIT-1a 4b / 4c: standing (as before) | install (the support-session step) | grant | close
        # | consent (OPEN-01: one action the updater decided from Invardia's consent channel)
        [ValidateSet('standing', 'install', 'grant', 'close', 'consent')][string]$Mode = 'standing',
        [int]$SupportHours = 0,
        [string]$Level = 'setup',
        [string]$ConsentLevel = '',
        [string]$Reason = '',
        [string]$TicketNumber = '',
        [string]$OpenedBy = '',
        # mode consent: ensure-read-user | remove-user | open-admin | close-admin; -UntilUtc the end of an open-admin
        [string]$ConsentAction = '',
        [string]$UntilUtc = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $p = [ordered]@{ ok = $false; problem = ''; identityResourceId = ''; identityName = ''; identityClientId = ''; identitySource = ''; pullIdentities = @()
                     sqlServer = ''; sqlDatabase = ''; image = ''; environmentId = ''; location = ''; appRoot = ''; script = ''; resource = $null; untilUtc = '' }
    try {
        if ($Mode -eq 'grant') {
            if ($SupportHours -lt 1 -or $SupportHours -gt (Get-PimSupportJitMaxHours)) { $p.problem = "the support access may last 1 to $(Get-PimSupportJitMaxHours) hours (asked: $SupportHours)"; return [pscustomobject]$p }
            if ((ConvertTo-PimSupportJitLevel "$Level") -notin @('troubleshoot', 'setup')) { $p.problem = "the level '$Level' is not troubleshoot or setup"; return [pscustomobject]$p }
            $Level = ConvertTo-PimSupportJitLevel "$Level"
            $p.untilUtc = Format-PimSupportJitUtc -Utc $NowUtc.ToUniversalTime().AddHours($SupportHours)
        }
        if ($Mode -eq 'install' -and -not (ConvertTo-PimSupportJitLevel "$ConsentLevel")) { $p.problem = "the consent level '$ConsentLevel' is not none, troubleshoot or setup"; return [pscustomobject]$p }
        if ($Mode -eq 'install') { $ConsentLevel = ConvertTo-PimSupportJitLevel "$ConsentLevel" }
        if ($Mode -eq 'standing' -and "$ConsentLevel".Trim()) {
            # OPEN-01: the read-only user records troubleshoot or setup; 'none' (no user at all) is -InstallSupportAccess -ConsentLevel none
            $ConsentLevel = ConvertTo-PimSupportJitLevel "$ConsentLevel"
            if ($ConsentLevel -notin @('troubleshoot', 'setup')) { $p.problem = "the read-only user records the consent level troubleshoot or setup (asked: '$ConsentLevel'); for no user at all run -InstallSupportAccess -ConsentLevel none"; return [pscustomobject]$p }
        }
        if ($Mode -eq 'consent') {
            if ("$ConsentAction" -notin @('ensure-read-user', 'remove-user', 'open-admin', 'close-admin')) { $p.problem = "the consent action '$ConsentAction' is not ensure-read-user, remove-user, open-admin or close-admin"; return [pscustomobject]$p }
            $ConsentLevel = ConvertTo-PimSupportJitLevel "$ConsentLevel"
            if (-not $ConsentLevel) { $p.problem = 'the consent level is not none, troubleshoot or setup'; return [pscustomobject]$p }
            if ($ConsentAction -eq 'open-admin') {
                # the admin access only with consent setup, and only until an end that lies ahead -- at most 8 h (the procedure checks it again)
                if ($ConsentLevel -ne 'setup') { $p.problem = "an admin access needs the consent level setup (it is '$ConsentLevel')"; return [pscustomobject]$p }
                $uu = ConvertFrom-PimSupportJitUtc "$UntilUtc"
                if (-not $uu -or $uu -le $NowUtc.ToUniversalTime()) { $p.problem = "the end of the admin access ('$UntilUtc') is not a UTC time ahead"; return [pscustomobject]$p }
                $cap = $NowUtc.ToUniversalTime().AddHours((Get-PimSupportJitMaxHours))
                if ($uu -gt $cap) { $uu = $cap }
                $p.untilUtc = Format-PimSupportJitUtc -Utc $uu
            }
        }
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
        if (-not $cid -and $Mode -eq 'close') {
            # 4b: the CLOSE may run as the ENGINE identity (-TemplateJobName <the engine job>): the signed revoke needs no owner
            # right, only EXECUTE. v2 (OPEN-01): the engine no longer opens anything -- a grant runs as the database job only.
            foreach ($es in @('AZURE_CLIENT_ID', 'PIM_ManagedIdentityClientId')) { if ("$($envMap[$es])".Trim()) { $cid = "$($envMap[$es])".Trim().ToLowerInvariant(); $src = "the identity $TemplateJobName runs as (its setting $es)"; break } }
        }
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
        $encoded = ConvertTo-PimSupportSqlJobCommand -Script $p.script

        $envList = @(
            @{ name = 'PIM_SqlServer'; value = $p.sqlServer }
            @{ name = 'PIM_SqlDatabase'; value = $p.sqlDatabase }
            @{ name = 'PIM_SUPPORTSQL_APP_ID'; value = "$SupportAppId".Trim().ToLowerInvariant() }
            @{ name = 'PIM_SUPPORTSQL_DB_USER'; value = "$DbUserName" }
            @{ name = 'PIM_SUPPORTSQL_MI_CLIENT_ID'; value = $cid }
        )
        $timeout = 604800
        if ($Mode -ne 'standing') {
            $envList += @(
                @{ name = 'PIM_SUPPORTSQL_MODE'; value = $Mode }
                @{ name = 'PIM_SUPPORTSQL_JIT_OPENED_BY'; value = (ConvertTo-PimSupportJitText -Text $OpenedBy -Max 120) }
            )
        }
        if ($Mode -eq 'install') { $envList += @(@{ name = 'PIM_SUPPORTSQL_CONSENT_LEVEL'; value = "$ConsentLevel" }) }
        if ($Mode -eq 'standing' -and "$ConsentLevel".Trim()) { $envList += @(@{ name = 'PIM_SUPPORTSQL_CONSENT_LEVEL'; value = "$ConsentLevel" }) }
        if ($Mode -eq 'consent') {
            # OPEN-01: one short run -- the action, Invardia's consent level, the end of an admin access; the job ends itself
            $envList += @(
                @{ name = 'PIM_SUPPORTSQL_CONSENT_ACTION'; value = "$ConsentAction" }
                @{ name = 'PIM_SUPPORTSQL_CONSENT_LEVEL'; value = "$ConsentLevel" }
                @{ name = 'PIM_SUPPORTSQL_JIT_UNTIL'; value = "$($p.untilUtc)" }
                @{ name = 'PIM_SUPPORTSQL_JIT_REASON'; value = (ConvertTo-PimSupportJitText -Text $Reason -Max 120) }
                @{ name = 'PIM_SUPPORTSQL_JIT_TICKET'; value = (ConvertTo-PimSupportJitText -Text $TicketNumber -Max 40) }
            )
            $timeout = 1800
        }
        if ($Mode -eq 'grant') {
            # the job holds until the end and then takes the access back; the platform ends it at the latest an hour after
            $envList += @(
                @{ name = 'PIM_SUPPORTSQL_JIT_LEVEL'; value = "$Level" }
                @{ name = 'PIM_SUPPORTSQL_JIT_HOURS'; value = "$([int]$SupportHours)" }
                @{ name = 'PIM_SUPPORTSQL_JIT_REASON'; value = (ConvertTo-PimSupportJitText -Text $Reason -Max 120) }
                @{ name = 'PIM_SUPPORTSQL_JIT_TICKET'; value = (ConvertTo-PimSupportJitText -Text $TicketNumber -Max 40) }
            )
            $timeout = ([int]$SupportHours * 3600) + 3600
        }
        $cfg = [ordered]@{ triggerType = 'Manual'; replicaTimeout = $timeout; replicaRetryLimit = 0; manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } }
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
        if ($p.untilUtc -and $Mode -eq 'grant') { $tags[(Get-PimSupportSqlJobUntilTagName)] = $p.untilUtc }   # a consent run never holds: it ends itself
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
      TIME-LIMITED (-Mode grant -SupportHours, SECAUDIT-1a): the job keeps running until that end and takes the access back by
      itself, so this run waits only for the job's RESULT line (the grant, read back by the job) and then LEAVES the job
      running until it has done that. A leftover that still holds a time-limited access (its tag
      pim-support-until is in the future) is removed only by another time-limited run, whose job then takes over the
      later of the two ends; a standing run stops instead.
      Never throws. Returns { ok; exit (0 done, 1 not done); whatIf; plan; leftover; jobCreated; jobRemoved; jobKept;
      execution; status; logLines; result; warnings; problems }.
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
        [ValidateSet('standing', 'install', 'grant', 'close', 'consent')][string]$Mode = 'standing',
        [int]$SupportHours = 0,
        [string]$Level = 'setup',
        [string]$ConsentLevel = '',
        [string]$Reason = '',
        [string]$TicketNumber = '',
        [string]$OpenedBy = '',
        [string]$ConsentAction = '',
        [string]$UntilUtc = '',
        [datetime]$NowUtc = [datetime]::UtcNow,
        [switch]$WhatIfOnly
    )
    $api = Get-PimSupportSqlJobAcaApi
    $jit = ($Mode -eq 'grant')
    $role = Get-PimSupportJitAdminRole          # the role a time-limited setup session adds (and takes back)
    $readRole = Get-PimSupportSqlRoleName       # OPEN-01: the Support app's only standing role
    $tagName = Get-PimSupportSqlJobTagName; $tagValue = Get-PimSupportSqlJobTagValue
    $rgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $jobPath = "$rgPath/providers/Microsoft.App/jobs/$JobName"
    $tplPath = "$rgPath/providers/Microsoft.App/jobs/$TemplateJobName"
    $notFound = '(?i)HTTP 404\b|ResourceNotFound|was not found|NotFound'
    $warnings = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    $res = [ordered]@{ ok = $false; exit = 1; whatIf = [bool]$WhatIfOnly; plan = $null; leftover = $false; jobCreated = $false; jobRemoved = $false; jobKept = $false
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
    $plan = Get-PimSupportSqlJobPlan -Template $tpl -TemplateJobName $TemplateJobName -JobName $JobName -SupportAppId $SupportAppId -DbUserName $DbUserName -SqlIdentityClientId $SqlIdentityClientId `
                -Mode $Mode -SupportHours $SupportHours -Level $Level -ConsentLevel $ConsentLevel -Reason $Reason -TicketNumber $TicketNumber -OpenedBy $OpenedBy -NowUtc $NowUtc `
                -ConsentAction $ConsentAction -UntilUtc $UntilUtc
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
            # a leftover that still holds a time-limited access is the job that takes it back: only a time-limited run may
            # replace it (its job takes over the later end); a standing run leaves it as it is and stops
            $oldUntil = ConvertFrom-PimSupportJitUtc -Value "$($tags[(Get-PimSupportSqlJobUntilTagName)])"
            if ($oldUntil -and $oldUntil -gt $NowUtc.ToUniversalTime() -and -not $jit) {
                $problems.Add("the job '$JobName' is running a time-limited support access that ends at $(Format-PimSupportJitUtc -Utc $oldUntil) and takes it back then -- it is not touched. Run again after that time. Nothing was changed.")
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
        if ($Mode -eq 'install') {
            Write-Host "What if: start it once. In the database $($plan.sqlDatabase) it records the customer's consent level '$ConsentLevel' for the Support app (SID $sid), gives the Support app's user [$DbUserName] read-only access, and installs the signed support access procedures (they take no user as a parameter); then it reads all of it back"
            Write-Host "What if: read the execution's result and its log lines, then remove the job '$JobName' and read back that it is gone"
        } elseif ($Mode -eq 'consent') {
            Write-Host "What if: start it once. It first takes back any time-limited support access whose end has passed"
            Write-Host "What if: in the database $($plan.sqlDatabase) it applies '$ConsentAction' for the consent level '$ConsentLevel' Invardia gave$(if ($plan.untilUtc) { " (admin until $($plan.untilUtc))" }), then reads the support access state back"
            Write-Host "What if: read the execution's result, then remove the job '$JobName' and read back that it is gone"
        } elseif ($Mode -eq 'close') {
            Write-Host "What if: start it once. It first takes back any time-limited support access whose end has passed"
            Write-Host "What if: in the database $($plan.sqlDatabase) it closes every open time-limited support access now: the roles the grant added are taken back, the Support app's open sessions end, the read-only access stays"
            Write-Host "What if: read the execution's result and its log lines, then remove the job '$JobName' and read back that it is gone"
        } elseif ($jit) {
            Write-Host "What if: start it once. It first takes back any time-limited support access whose end has passed"
            Write-Host "What if: in the database $($plan.sqlDatabase) it asks for level '$Level' for $SupportHours hour(s); the level given is the lower of that and the customer's consent; for $role the end ($($plan.untilUtc)) is recorded with the role; a role the user held before is never taken away"
            Write-Host "What if: read the job's result, then leave the job running: at $($plan.untilUtc) it takes $role back by itself (the read-only access stays) and ends"
        } else {
            Write-Host "What if: start it once. It first takes back any time-limited support access whose end has passed"
            Write-Host "What if: in the database $($plan.sqlDatabase) it runs the support access step (consent '$(if ("$ConsentLevel".Trim()) { (ConvertTo-PimSupportJitLevel "$ConsentLevel") } else { 'as recorded, else troubleshoot' })'): the user [$DbUserName] from the Support app's client id (SID $sid) when no user has that id, in $readRole only (read-only); an existing user of the Support app is reused whatever its name; no database owner role and no SQL admin group membership is given"
            Write-Host "What if: read the execution's result and its log lines, then remove the job '$JobName' and read back that it is gone"
        }
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
            & $say "created: the one-time job '$JobName' (running as $($plan.identityName); $(if ($jit) { "it ends after it has taken the access back at $($plan.untilUtc)" } else { 'removed again at the end' }))" 'Yellow'

            # ---- 4. start it once and wait
            $started = & $Arm 'POST' "${jobPath}/start?api-version=$api" @{}
            $exec = if ($started) { "$($started.name)".Trim() } else { '' }
            if (-not $exec) { throw "the job '$JobName' did not start (no execution was returned)" }
            $res.execution = $exec
            & $say "started: execution $exec -- waiting (at most $TimeoutSeconds seconds)"
            $tries = [Math]::Max(1, [int][Math]::Ceiling($TimeoutSeconds / [double][Math]::Max(1, $PollSeconds)))
            $status = ''; $lastErr = ''
            # time-limited: the job keeps running until the end, so the wait is for its RESULT line, read while it runs
            $ws = ''; $jitLines = @(); $jitRefused = 0
            if ($jit -and $Logs) { try { $envObj = & $get $plan.environmentId; if ($envObj) { $ws = "$($envObj.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim() } } catch { $ws = '' } }
            for ($i = 0; $i -lt $tries; $i++) {
                & $Sleep $PollSeconds
                try { $x = & $get "$jobPath/executions/$exec"; $status = if ($x) { "$($x.properties.status)".Trim() } else { '' } } catch { $lastErr = & $first $_ }
                if ($status -in $final) { break }
                if ($jit -and $ws -and $jitRefused -lt 2) {
                    try { $jitLines = @(& $Logs $ws $exec | ForEach-Object { "$_" }); $jitRefused = 0 } catch { $jitLines = @(); $jitRefused++ }
                    if (@($jitLines | Where-Object { $_ -match '\[supportsql\] RESULT ' }).Count) { break }
                }
            }
            $res.status = $status

            # ---- 5. the console lines (they reach the workspace late; a missing log never turns a result around)
            $lines = @()
            if ($jit -and $status -notin $final) { $lines = @($jitLines) }
            elseif ($Logs -and $status -in $final) {
                if (-not $ws) { try { $envObj = & $get $plan.environmentId; if ($envObj) { $ws = "$($envObj.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim() } } catch { $ws = '' } }
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
            $revokeLine = @($log.lines | Where-Object { $_ -match '\[supportsql\] REVOKE \{' }) | Select-Object -Last 1
            if ($jit -and $status -notin $final) {
                # the job holds the time-limited access and takes it back at the end by itself: it is NOT stopped or removed
                $res.jobKept = $true
                if ($r -and [bool]$r.ok) {
                    if ("$($r.state)" -eq 'read-only') {
                        & $say "the level given is read-only (asked '$($r.requested)', consented '$($r.consented)'): nothing was added; the job ends by itself" 'Green'
                    } elseif ("$($r.state)" -eq 'pre-existing') {
                        & $say "the Support app's database user already held $role before this grant -- it is recorded until $($r.untilUtc) and is NOT taken away then" 'Green'
                    } else {
                        & $say "the Support app's database user (SID $sid): $role until $($r.untilUtc) (asked '$($r.requested)', consented '$($r.consented)')$(if ("$($r.state)" -eq 'extended') { ' -- an open access was extended to the later end' }); read-only access kept (read back by the job)" 'Green'
                        & $say "the job '$JobName' keeps running and takes $role back at $($r.untilUtc) by itself; the read-only access stays" 'Green'
                    }
                } elseif ($r) {
                    $problems.Add("the job's result line says the time-limited access was not put in place ($($r.problem)) -- treated as NOT done")
                } else {
                    $problems.Add("the job is running (execution $exec) but its result line could not be read within $TimeoutSeconds seconds, so the time-limited access is NOT confirmed. The job is left running: it takes back whatever it gave at $($plan.untilUtc) by itself.")
                }
            } elseif ($Mode -in @('install', 'close', 'consent') -and $status -eq 'Succeeded' -and $r -and [bool]$r.ok) {
                if ($Mode -eq 'consent') { & $say "consent: '$($r.action)' applied and read back by the job (consent '$($r.consented)', read-only $($r.readOnly), admin open $($r.jitOpen)$(if ("$($r.jitUntil)") { " until $($r.jitUntil)" }))" 'Green' }
                elseif ($Mode -eq 'install') { & $say "installed: the signed support access procedures (read back by the job: current, signed, private key removed, ALTER denied); consent '$($r.consented)'" 'Green' }
                else { & $say "closed: $($r.closed) open support access grant(s) (only roles the grant added were taken back; $($r.sessionsEnded) session(s) ended)$(if ("$($r.state)" -eq 'not-installed') { ' -- the time-limited access is not installed here' })" 'Green' }
            } elseif ($jit -and $status -eq 'Succeeded' -and $revokeLine) {
                & $say "the job gave the time-limited access and has already taken it back (its end has passed): $($revokeLine.Trim())" 'Green'
            } elseif ($status -eq 'Succeeded' -and $r -and -not [bool]$r.ok) {
                $problems.Add("the execution $exec ended Succeeded but its result line says it did not put the user in place ($($r.problem)) -- treated as NOT done")
            } elseif ($status -eq 'Succeeded') {
                if ($r) {
                    $what = switch ("$($r.state)") { 'created' { 'created' } 'in-place' { 'was already there' } default { 'in place' } }
                    & $say "database user [$($r.userName)] (the Support app's client id, SID $sid): $what; in $readRole only, consent '$($r.consented)' (read back by the job)" 'Green'
                    # OPEN-01: what an EARLIER version gave is said (a WARNING), never kept as "in place", never removed here
                    $lt = Get-PimSupportSqlLegacyText -Legacy @(@($r.legacy) | Where-Object { "$_".Trim() }) -SessionOpen ([bool]$r.sessionOpen)
                    if ($lt) { $warnings.Add($lt) }
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
        # ---- 6. the job is removed and read back -- also after a failed step. NOT while it holds a time-limited access:
        # it takes that back at the end by itself and then ends.
        if ($res.jobKept) {
            $warnings.Add("the one-time job '$JobName' stays in resource group $ResourceGroup until $($plan.untilUtc): it takes the time-limited access back then and ends. The next run of this script removes it.")
        } elseif ($res.jobCreated) {
            $left = & $remove
            if (-not $left) { $res.jobRemoved = $true; & $say "removed: the one-time job '$JobName' (read back: it is gone)" 'Green' }
            else { $problems.Add("the one-time job '$JobName' is STILL in resource group $ResourceGroup ($left). It carries the SQL admin identity and does nothing until it is started; remove it: Azure portal > resource group $ResourceGroup > $JobName > Delete -- or run this script again, which removes it first.") }
        }
    }
    return (& $finish)
}
