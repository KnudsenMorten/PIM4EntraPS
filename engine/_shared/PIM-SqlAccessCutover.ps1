# =================================================================================================
# PIM-SqlAccessCutover.ps1 -- framework §12.23 P8 EXCEPTION (owner 2026-10-18: "Updater, next release" / "then i dont
# have to do anything" / "you decide"): a PRIVATE-SQL install that was never cut over is moved by its own UPDATER, which
# starts the install's in-network admin job (ca-pim-dbinit) -- run 1, then on a later update run 2. The Support app has
# no route to a private database; the customer is not asked to do anything.
#
# 🔒 The updater runs NO admin SQL itself (Test-PimSqlAccess L4): it reads (as dbo, while it is still in the SQL admin
# group), decides (Get-PimSqlAccessCutoverStep, PURE) and starts the job. The job does the admin SQL with the same product
# code as the Support-app cut-over (Invoke-PimSqlAccessInstall / Invoke-PimSqlAccessRun2), reads every step back and logs
# it. NEVER throws: a cut-over that cannot run leaves the install on the broad roles, exactly as before.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary.
# =================================================================================================

Set-StrictMode -Off

function Get-PimSqlCutoverAdminJobName { return 'ca-pim-dbinit' }

function Get-PimAcaImageTag {
    <# PURE. The tag of a Container Apps job / app's first container image ('' when unreadable). #>
    param([AllowNull()][object]$Resource)
    try { $img = "$(@($Resource.properties.template.containers)[0].image)" } catch { $img = '' }
    if ($img -notmatch ':([^:/@]+)$') { return '' }
    return $Matches[1]
}

function Invoke-PimSqlAccessCutoverStep {
    <#
      The updater's half. Reads, decides, and -- only for 'run1' / 'run2' -- sets the admin job's PIM_DBINIT_SQL_ACCESS
      ({ updaterUserName; updaterAppId; run2 }) and starts ONE execution, then waits for it (bounded) and reports.
        -SqlServer          the store's server FQDN (or name); -Query (cs, sql) reads the store as the updater
        -UpdaterJob         this job's name (its contained user is created by run 1); -UpdaterAppId: its client id
        -Arm (method, path, body): ARM seam; -Sleep (seconds): wait seam; -Start (sub, rg, name): job start seam
      Returns { step; reason; started; execution; status; lines[] }. Never throws.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [AllowEmptyString()][string]$SqlServer,
        [AllowEmptyString()][string]$ConnectionString,
        [Parameter(Mandatory)][scriptblock]$Query,
        [Parameter(Mandatory)][string]$UpdaterJob,
        [AllowEmptyString()][string]$UpdaterAppId,
        [Parameter(Mandatory)][scriptblock]$Arm,
        [scriptblock]$Sleep,
        [scriptblock]$Start,
        [scriptblock]$SetEnv,
        [string]$AdminJob = (Get-PimSqlCutoverAdminJobName),
        [int]$WaitSeconds = 900,
        [int]$PollSeconds = 20,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $out = [ordered]@{ step = 'none'; reason = ''; started = $false; execution = ''; status = ''; lines = $null }
    $fin = { $out.lines = @($lines.ToArray()); return [pscustomobject]$out }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    try {
        $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        # ---- private SQL? (the server in this resource group whose name matches the store's) ---------------------------
        $srvName = ("$SqlServer".Trim() -split '\.')[0]
        $private = $false
        if ($srvName) {
            $srv = @(@(& $Arm 'GET' "$base/providers/Microsoft.Sql/servers?api-version=2021-11-01" $null) | ForEach-Object { if ($_.PSObject.Properties['value']) { @($_.value) } else { $_ } } |
                     Where-Object { $_ -and "$($_.name)" -ieq $srvName })[0]
            if ($srv) { $private = ("$($srv.properties.publicNetworkAccess)" -eq 'Disabled') }
            else { [void]$lines.Add("SQL server '$srvName' is not in $ResourceGroup -- treated as not private (no cut-over from here)") }
        }
        # ---- the store, read as the updater ------------------------------------------------------------------------------
        $me = @(& $Query $ConnectionString "SELECT IS_ROLEMEMBER('db_owner') AS dbOwner, USER_NAME() AS userName;")[0]
        $isAdmin = ($me -and ("$($me.dbOwner)" -eq '1' -or "$($me.userName)" -eq 'dbo'))
        $nm = Get-PimSqlAccessInstallNameMap
        $row = @(& $Query $ConnectionString (Get-PimSqlAccessSetupGateSql -UserNames (@($nm['pim_web']) + @($nm['pim_engine']))))[0]
        $hasProc = ($row -and "$($row.hasProc)" -eq '1')
        $broad = $(if ($row) { $row.broadUsers } else { $null })
        $signerUtc = $null; $green = $null
        if ($hasProc -and $isAdmin) {
            $parts = (Get-PimSqlAccessStateSql) -split ';\s*\r?\nSELECT r\.name', 2
            $facts = @(& $Query $ConnectionString ($parts[0] + ';'))[0]
            if ($facts) { $signerUtc = Get-PimSqlAccessSignerUtc -Signer "$($facts.signer)" }
            if ($null -ne $signerUtc) {
                $hist = @(& $Query $ConnectionString "SELECT CAST(ValueJson AS nvarchar(max)) AS v FROM pim.Settings WHERE Name = N'JobRunHistory';")[0]
                $runs = @()
                if ($hist -and "$($hist.v)".Trim()) { $tmp = "$($hist.v)" | ConvertFrom-Json; if ($tmp -is [string]) { $tmp = $tmp | ConvertFrom-Json }; $runs = @($tmp) }
                $green = Test-PimSqlAccessRunsGreenSince -Runs $runs -SinceUtc $signerUtc
            }
        }
        # ---- the in-network admin job: there, and on THIS release (the self job's tag) ------------------------------------
        $jobOk = $false; $job = $null
        try { $job = & $Arm 'GET' "$base/providers/Microsoft.App/jobs/$AdminJob`?api-version=2024-03-01" $null } catch { $job = $null }
        if ($job) {
            $self = $null; try { $self = & $Arm 'GET' "$base/providers/Microsoft.App/jobs/$UpdaterJob`?api-version=2024-03-01" $null } catch { $self = $null }
            $jt = Get-PimAcaImageTag -Resource $job; $st = Get-PimAcaImageTag -Resource $self
            $jobOk = ($jt -and $st -and $jt -eq $st)
            if (-not $jobOk) { [void]$lines.Add("admin job $AdminJob runs '$jt', this updater '$st' -- it must be on this release first") }
        }
        $d = Get-PimSqlAccessCutoverStep -PrivateSql $private -AdminJobOk $jobOk -UpdaterIsAdmin ([bool]$isAdmin) -HasProc $hasProc -BroadUsers $broad `
                 -SignerUtc $signerUtc -RunsGreen $green -NowUtc $NowUtc
        $out.step = $d.step; $out.reason = $d.reason
        if ($d.step -eq 'none') { return (& $fin) }
        if ("$UpdaterAppId" -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            $out.step = 'none'; $out.reason = "$($d.step) is due, but this updater's own client id is unknown -- its database user cannot be named; nothing started"
            return (& $fin)
        }
        # ---- set the admin run's setting (one write, read back) and start ONE execution ----------------------------------
        $want = ConvertTo-Json -Compress -InputObject ([ordered]@{ updaterUserName = $UpdaterJob; updaterAppId = "$UpdaterAppId".ToLowerInvariant(); run2 = ($d.step -eq 'run2') })
        if (-not $SetEnv) { $SetEnv = { param($s, $r, $j, $v) Set-PimAcaJobEnvValues -SubscriptionId $s -ResourceGroup $r -JobName $j -Values $v } }
        [void](& $SetEnv $SubscriptionId $ResourceGroup $AdminJob ([ordered]@{ PIM_DBINIT_SQL_ACCESS = $want }))
        [void]$lines.Add("$AdminJob PIM_DBINIT_SQL_ACCESS = $want (read back)")
        if (-not $Start) { $Start = { param($s, $r, $j) Start-PimAcaJobExecution -SubscriptionId $s -ResourceGroup $r -Name $j } }
        $st = & $Start $SubscriptionId $ResourceGroup $AdminJob
        if (-not $st.ok) { $out.status = 'not started'; [void]$lines.Add("could not start $AdminJob`: $($st.reason)"); return (& $fin) }
        $out.started = $true; $out.execution = "$($st.execution)"
        [void]$lines.Add("started $AdminJob execution $($st.execution) ($($d.step))")
        # ---- wait for it (bounded); its own log carries every statement and read-back ------------------------------------
        $waited = 0
        while ($waited -lt $WaitSeconds) {
            & $Sleep $PollSeconds; $waited += $PollSeconds
            $ex = $null
            try { $ex = & $Arm 'GET' "$base/providers/Microsoft.App/jobs/$AdminJob/executions/$($st.execution)?api-version=2024-03-01" $null } catch { $ex = $null }
            $s = if ($ex) { "$($ex.properties.status)" } else { '' }
            if ($s -in @('Succeeded', 'Failed', 'Stopped', 'Degraded')) { $out.status = $s; break }
        }
        if (-not $out.status) { $out.status = "still running after $WaitSeconds s" }
        [void]$lines.Add("$AdminJob execution $($st.execution): $($out.status)")
    } catch {
        $out.reason = "not checked: $($_.Exception.Message)"
        if ($out.step -ne 'none' -and -not $out.started) { $out.step = 'none' }
    }
    return (& $fin)
}
