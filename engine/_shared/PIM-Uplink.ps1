#Requires -Version 5.1
<#
.SYNOPSIS
  §95.3 -- PIM's status telemetry (job 'uplink'): a HEARTBEAT every hour and one RUN report per job that ran, sent to the
  Invardia-hosted uplink through the FRAMEWORK client (sync/_AitUplink.ps1 Schema 2; a byte-identical copy ships as
  engine/_shared/AitUplink.framework.ps1 because sync/ is never in the container -- Test-PimUplink pins the copy).
  Contract: Invardia docs/design/TELEMETRY-UPLINK.md (owner decisions 2026-10-03); framework DOCS/REQUIREMENTS.md §8.

.DESCRIPTION
  WHO SENDS WHAT
    * no install key   -> ANONYMOUS: the public community code; no tenant, no host, no error text; error CLASS and bucketed
                          counts only; a random TelemetryInstallId (its OWN id -- never the licence request's InstallId,
                          which travels next to the tenant id, so the two cannot be joined at Invardia).
    * PIM_UPLINK_KEY   -> IDENTIFIED (Pro / trial): the per-install key Invardia issued, delivered as a Container Apps
                          secret (secretref) -> environment variable. The key proves the environment; the tenant in the
                          body is only compared for mismatch. Error text shortened + redacted before it leaves.
  WHEN
    * heartbeat: every hour (owner 2026-10-12, PIM 100.103; was 4 h, 24 h before). Identified only: InstallRole
      single | managing | managed (+ ManagingTenantId) and the setup Controls, each with checkedUtc and, for unknown, a
      reason (lane repfix, additive -- see Test-PimUplinkAdditiveEnabled). Identified only (PIM 100.36): Counts { sqlUsedMb, sqlMaxMb } -- the store's allocated data
      pages and max size, MB (Get-PimUplinkSqlSpace); a failed / empty read leaves both out, never a 0.
      Identified only (PIM 100.128): the adoption counts in Counts (managedAdmins ... hybridServers, Get-PimUplinkAdoptionCounts)
      -- COUNT queries on the store, run once per heartbeat; an unreadable source leaves its key out, never a 0.
      Identified only (PIM 100.56, framework 8.9): Endpoints [ { kind; url; label? } ] -- the Manager, the RFA portal, the
      access request API, the MCP server, each only where it exists (Get-PimUplinkEndpoints); a guard record's Link is a deep
      link into that Manager (Get-PimGuardLink, PIM-Guard.ps1).
    * run: per job NAME, the newest finished run since the last send; Outcome = failed if ANY run of it failed since,
      warning if one was held, else ok. One report per job per cycle -- never one per run: rfa-sync runs every tick and
      Invardia allows 30 POSTs a minute per IP (shared behind a NAT): at most 20 per cycle, 2.5 s apart,
      the first failure stops the cycle, and each job keeps its own watermark so nothing is skipped or sent twice.
    * skipped / unimplemented / running runs are not reported (nothing ran), and the uplink job never reports itself.
    * setup (PIM 100.10, framework 8.7): identified only, feature 'telemetry.setup', daily + on every change -- the control
      list, permission counts (+ Get Started steps / findings with PIM_UPLINK_SETUP_EXTENDED=1). PIM-UplinkSetup.ps1.
    * guards (PIM 100.102): the IDENTIFIED heartbeat carries ActiveGuards -- what the guards hold right now ([] = nothing;
      left out when the state could not be read) -- and a guard that was reported and is no longer held gets ONE Kind
      'guard' record with GuardOutcome 'cleared' (ClearedUtc, ClearedBy only where the stored state proves it).
      The set of reported guards is UplinkState.guardsReported.
    * every record carries Ring: PIM_UPDATE_RING, else the ring recorded in pim.Settings['UpdateState'] (Resolve-PimUplinkRing).
  🔒 Gated by the feature 'telemetry.uplink', which is ON by default (defaultEnabled=$true in PIM-FeatureCatalog.ps1;
     owner decision 2026-10-04, framework UPDATE-1.4) and depends on 'scheduler.jobs'. Switching it off sends ONE opt-out.
  🔒 A failed send never fails anything else: the job keeps its watermark (the runs are sent on the next cycle) and the
     next heartbeat is not skipped. PIM 100.75 (HOGYM 2026-10-11: a managed install sent NOTHING and the Jobs page was
     green): a send that failed, or an install that should be identified but sends anonymously (no / a malformed install
     key on a licensed install), is a WARNING run (amber on the Jobs page, one alert mail a day at most) -- never a failed
     run (framework 12.18 / 12.21: a telemetry problem is not an engine failure). Get-PimUplinkDeliveryWarning decides.
#>

$script:PimUplinkProduct = 'pim-manager'
# Invardia's limit (2026-10-04): 30 POSTs per MINUTE per client IP -- and several installs behind one NAT share it. So at most
# 20 reports per cycle, ~2.5 s apart (the job passes -PauseMs 2500), and the cycle STOPS at the first failure (a 429 says
# wait): what was not sent keeps its per-job watermark and goes next cycle.
$script:PimUplinkMaxRunsPerCycle = 20

function Get-PimUplinkJobId {
    <# PURE. The stable Job id Invardia stores: 'pim-' + the job TYPE (one-off trigger names collapse onto their type). #>
    param([AllowNull()][object]$Run)
    $t = "$($Run.type)".Trim().ToLowerInvariant()
    if (-not $t) { $t = "$($Run.name)".Trim().ToLowerInvariant() }
    $t = ($t -replace '[^a-z0-9.-]', '-').Trim('-')
    if (-not $t) { return '' }
    return "pim-$t"
}

function Get-PimUplinkRunOutcome {
    <# PURE. ok | warning | failed | '' (not reportable: skipped, unimplemented, still running, nothing ran). #>
    param([AllowNull()][object]$Run)
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    # PIM 100.166 (b): a run a person CANCELLED is a deliberate act, not an outcome of the product -- not reported.
    if ($st -in @('running', 'skipped', 'unimplemented', 'outofscope', 'disabled', 'cancelled', '')) { return '' }
    # §95.2o: an INTERRUPTED run (the scheduler restarted for an update, the platform stopped the execution) is not a
    # product failure -- reported as a warning, never as a failed run (Invardia fix request d0217f96).
    if ($st -eq 'interrupted') { return 'warning' }
    # §100.45: a THROTTLED run (Microsoft rate-limited it, nothing applied, retried) is normal -- a warning with ErrorClass
    # 'throttled', never a failed run, so it never opens a fix request (owner 2026-10-10). Checked before ok: it carries ok=false.
    if ($st -eq 'throttled') { return 'warning' }
    if ($st -eq 'failed' -or ($Run.PSObject.Properties['ok'] -and -not [bool]$Run.ok)) { return 'failed' }
    if ($Run.PSObject.Properties['held'] -and [bool]$Run.held) { return 'warning' }
    if ($st -eq 'held') { return 'warning' }
    if ($st -eq 'warning') { return 'warning' }   # PIM 100.75: a run that declared a warning about itself
    return 'ok'
}

function Get-PimUplinkRunPlan {
    <#
      PURE. From the job run history (any order) and the watermarks, ALL run reports due, failures first, then oldest first:
      @{ reports = @( @{ job; outcome; durationMs; errorText; finishedUtc; runCount } ); watermarkUtc = <newest finishedUtc seen> }
      A run counts when it FINISHED after its job's own watermark (-SinceByJob['pim-<type>']), else after -SinceUtc.
      ONE WATERMARK PER JOB, not one for all: a cycle may send only some reports (the rate limit), and a single watermark
      would then skip the jobs that were not sent. The 'uplink' job itself is left out (it would report itself forever).
    #>
    param([object[]]$Runs = @(), [AllowNull()][object]$SinceUtc, [hashtable]$SinceByJob = @{})
    $since = $null; try { if ($SinceUtc) { $since = ([datetime]$SinceUtc).ToUniversalTime() } } catch { $since = $null }
    $byJob = [ordered]@{}
    $newest = $since
    # PIM 100.143 RUN-NO-RESULT: a run whose execution ended without its record (closed 'interrupted', cause 'unrecorded') is
    # a WARNING with that class -- never "failed, unclassified". TWO in a row of the same job (by name, the run before it of
    # that job, any watermark) are FAILED with that class: the rule the Jobs view applies (Get-PimJobsStatus).
    $isNoResult = { param($x) "$($x.status)".Trim().ToLowerInvariant() -eq 'interrupted' -and $x.PSObject.Properties['interruptedCause'] -and "$($x.interruptedCause)".Trim().ToLowerInvariant() -eq 'unrecorded' }
    $noResultTwice = @{}
    $byName = @{}
    foreach ($x in @($Runs | Where-Object { $_ -and "$($_.finishedUtc)".Trim() -and "$($_.status)".Trim().ToLowerInvariant() -notin @('running', 'skipped', 'unimplemented', 'outofscope', 'disabled', '') })) {
        $nm = "$($x.name)"; if (-not $byName.ContainsKey($nm)) { $byName[$nm] = New-Object System.Collections.Generic.List[object] }; $byName[$nm].Add($x)
    }
    foreach ($nm in @($byName.Keys)) {
        $seq = @($byName[$nm] | Sort-Object { "$($_.startedUtc)" })
        for ($k = 1; $k -lt $seq.Count; $k++) { if ((& $isNoResult $seq[$k]) -and (& $isNoResult $seq[$k - 1])) { $noResultTwice["$($seq[$k].runId)"] = $true } }
    }
    foreach ($r in @($Runs | Where-Object { $_ })) {
        $fin = $null; try { if ("$($r.finishedUtc)") { $fin = ([datetime]"$($r.finishedUtc)").ToUniversalTime() } } catch { $fin = $null }
        if (-not $fin) { continue }
        $job = Get-PimUplinkJobId -Run $r
        if (-not $job -or $job -eq 'pim-uplink') { continue }
        $js = $since
        if ($SinceByJob -and $SinceByJob.ContainsKey($job)) { try { $js = ([datetime]"$($SinceByJob[$job])").ToUniversalTime() } catch { } }
        if ($js -and $fin -le $js) { continue }
        $out = Get-PimUplinkRunOutcome -Run $r
        if (-not $out) { continue }
        if ("$($r.runId)".Trim() -and $noResultTwice.ContainsKey("$($r.runId)")) { $out = 'failed' }   # 100.143: the second in a row
        if (-not $newest -or $fin -gt $newest) { $newest = $fin }
        if (-not $byJob.Contains($job)) { $byJob[$job] = @{ job = $job; latest = $r; latestFin = $fin; failed = $null; held = $false; throttled = $null; noResult = $null; count = 0 } }
        $e = $byJob[$job]; $e.count++
        if ($fin -gt $e.latestFin) { $e.latest = $r; $e.latestFin = $fin }
        if ($out -eq 'failed' -and (-not $e.failed -or $fin -gt ([datetime]"$($e.failed.finishedUtc)").ToUniversalTime())) { $e.failed = $r }
        if ($out -eq 'warning') {
            $e.held = $true
            # PIM 100.99: WHICH kind of warning (for Outcome / ActionBy) -- the one that needs a person wins, then the newest.
            $stx = "$($r.status)".Trim().ToLowerInvariant()
            $wk = 'held'; $rank = 4
            if ($stx -eq 'warning') { $wk = 'warning'; $rank = 3 } elseif ($stx -eq 'throttled') { $wk = 'throttled'; $rank = 2 } elseif ($stx -eq 'interrupted') { $wk = 'interrupted'; $rank = 1 }
            if (-not $e.ContainsKey('kindRank') -or $rank -gt [int]$e.kindRank -or ($rank -eq [int]$e.kindRank -and $fin -gt $e.kindFin)) { $e.kind = $wk; $e.kindRank = $rank; $e.kindRun = $r; $e.kindFin = $fin }
        }
        if ("$($r.status)".Trim().ToLowerInvariant() -eq 'throttled' -and (-not $e.throttled -or $fin -gt ([datetime]"$($e.throttled.finishedUtc)").ToUniversalTime())) { $e.throttled = $r }
        if ($out -eq 'warning' -and (& $isNoResult $r) -and (-not $e.noResult -or $fin -gt ([datetime]"$($e.noResult.finishedUtc)").ToUniversalTime())) { $e.noResult = $r }
    }
    $reports = New-Object System.Collections.Generic.List[object]
    # Failures first (they matter most when the rate limit leaves some for the next cycle), then the oldest first.
    $order = @($byJob.Keys | Sort-Object @{ Expression = { if ($byJob[$_].failed) { 0 } else { 1 } } }, @{ Expression = { $byJob[$_].latestFin } }, @{ Expression = { $_ } })
    foreach ($k in $order) {
        $e = $byJob[$k]
        $outcome = if ($e.failed) { 'failed' } elseif ($e.held) { 'warning' } else { 'ok' }
        # A failure is reported WITH the failing run's text, even when a later run of the same job succeeded.
        $src = if ($e.failed) { $e.failed } else { $e.latest }
        $dur = $null; if ($src.PSObject.Properties['durationMs']) { $dur = $src.durationMs }
        $txt = if ($outcome -eq 'failed') { "$($src.detail)" } else { '' }
        # §100.45: a warning because Microsoft throttled the job carries ErrorClass THROTTLED (and the throttled run's text).
        # PIM 100.143: a warning because a run's record was lost carries ErrorClass RUN-NO-RESULT (throttling, if any, wins);
        # a failure that IS the second RUN-NO-RESULT in a row carries it too (never left to the text classifier).
        $cls = ''
        if ($outcome -eq 'warning' -and $e.throttled) { $cls = 'THROTTLED'; $txt = "$($e.throttled.detail)" }
        elseif ($outcome -eq 'warning' -and $e.noResult) { $cls = 'RUN-NO-RESULT'; $txt = "$($e.noResult.detail)" }
        if ($outcome -eq 'failed' -and (& $isNoResult $src)) { $cls = 'RUN-NO-RESULT' }
        # PIM 100.99 (additive; the keys above are unchanged): kind = failed | held | warning | throttled | interrupted | '',
        # noteText = what that run said (a held run's detail, a declared warning's summary), warningKind, updateAction.
        $kind = ''; $note = ''; $wkind = ''
        if ($outcome -eq 'failed') { $kind = 'failed'; $note = $txt }
        elseif ($outcome -eq 'warning' -and $e.ContainsKey('kind')) {
            $kind = "$($e.kind)"; $kr = $e.kindRun
            if ($kind -eq 'warning') {
                if ($kr.PSObject.Properties['warningKind']) { $wkind = "$($kr.warningKind)" }
                if ($kr.PSObject.Properties['warningSummary'] -and "$($kr.warningSummary)".Trim()) { $note = "$($kr.warningSummary)" } else { $note = "$($kr.detail)" }
            } elseif ($kind -in @('held', 'throttled')) { $note = "$($kr.detail)" }
        }
        $ua = ''; if ($src.PSObject.Properties['updateAction']) { $ua = "$($src.updateAction)" }
        [void]$reports.Add(@{ job = $e.job; outcome = $outcome; durationMs = $dur; errorText = $txt; errorClass = $cls; finishedUtc = $e.latestFin.ToString('o'); runCount = $e.count
                              kind = $kind; noteText = $note; warningKind = $wkind; updateAction = $ua })
    }
    $wm = $null; if ($newest) { $wm = ([datetime]$newest).ToString('o') }
    $arr = $reports.ToArray()
    return @{ reports = $arr; watermarkUtc = $wm }
}

# Owner 2026-10-12, relayed by Invardia (PIM 100.103: "telemetry must include this more frequent"; his choice in Invardia's
# wizard: heartbeat "Hourly") -- every HOUR (was every 4 h since 2026-10-10, 24 h before). Invardia allows 30 POSTs a minute
# per IP; one heartbeat an hour is far inside that. The job 'uplink' itself runs every 60 minutes from a 5-minute tick, so
# two runs are 60 minutes apart give or take a tick: the heartbeat is due from 50 minutes after the last one (a strict
# 60 would skip every other run and make it two-hourly).
$script:PimUplinkHeartbeatHours = 1
function Get-PimUplinkHeartbeatHours { <# PURE. The heartbeat interval in hours -- a literal (child-scope safe). #> return 1 }
function Get-PimUplinkHeartbeatDue {
    <# PURE. True when no heartbeat was sent in the last hour (less 10 minutes for the tick) -- or ever. #>
    param([AllowNull()][object]$LastHeartbeatUtc, [datetime]$NowUtc = [datetime]::UtcNow, [double]$Hours = (Get-PimUplinkHeartbeatHours))
    if (-not $Hours -or $Hours -le 0) { $Hours = 1 }
    try { if ("$LastHeartbeatUtc") { return ($NowUtc.ToUniversalTime() -ge ([datetime]"$LastHeartbeatUtc").ToUniversalTime().AddMinutes(($Hours * 60) - 10)) } } catch { }
    return $true
}

function Get-PimUplinkEdition {
    <# PURE. community | pro | trial, from the licence verdict for THIS tenant (a Pro-Trial sku is 'trial'). #>
    param([AllowNull()][object]$License, [bool]$ProHere)
    if (-not $ProHere) { return 'community' }
    if ("$($License.Sku)".Trim() -match '(?i)trial') { return 'trial' }
    return 'pro'
}

function Get-PimUplinkLicenceState {
    <# PURE. valid | grace | expired | none (Invardia's closed list). #>
    param([AllowNull()][object]$License)
    switch ("$($License.Status)") { 'Valid' { 'valid' } 'Grace' { 'grace' } 'Expired' { 'expired' } default { 'none' } }
}

function Get-PimUplinkErrorClass {
    <#
      The failure catalog code for a failed run's text, lower-cased by the framework. Invardia's ErrorClass list is closed by
      SHAPE ([a-z0-9-]{1,40}, packages/core uplink.ts); the catalog codes are its values.
      🔴 100.34 (Invardia triage 2026-10-09: 11 of 12 PIM fix requests titled "unclassified"). A failed run's text is the
      job SUMMARY (Format-PimFailureSummary: "3 item(s) failed: 2x <title> [WORKLOAD-RESOURCE-MISSING]; 1x ..."), not a raw
      error, so the catalog's raw-error rules matched nothing and every classified failure went up as UNCLASSIFIED. The
      code the engine already put in brackets wins -- the first known one, which is the largest group (the summary is
      sorted by count); UNCLASSIFIED only when the engine itself said so or nothing is known. A convergence verdict is
      CONVERGENCE. Only then is the raw text classified.
    #>
    param([string]$Text)
    if (-not "$Text".Trim()) { return '' }
    $known = @{}
    if (Get-Command Get-PimFailureCatalogCodes -ErrorAction SilentlyContinue) { try { foreach ($c in @(Get-PimFailureCatalogCodes)) { $known["$c"] = $true } } catch { } }
    foreach ($m in [regex]::Matches("$Text", '\[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\]')) {
        $code = $m.Groups[1].Value
        if ($code -ne 'UNCLASSIFIED' -and $known.ContainsKey($code)) { return $code }
    }
    if ("$Text" -match '(?i)CONVERGENCE FAILURE') { return 'CONVERGENCE' }
    if (Get-Command Get-PimFailureClassification -ErrorAction SilentlyContinue) {
        try { $c = "$((Get-PimFailureClassification -Message $Text).code)"; if ($c) { return $c } } catch { }
    }
    return 'UNCLASSIFIED'
}

function Get-PimUplinkFixKind {
    <#
      100.34. customer-config | product-defect for an ErrorClass, from the failure catalog (Get-PimFailureFixKind). Invardia
      raises a fix request only for product defects and shows customer-config items to support. '' for a run with no class.
    #>
    param([string]$ErrorClass)
    $c = "$ErrorClass".Trim(); if (-not $c) { return '' }
    if (Get-Command Get-PimFailureFixKind -ErrorAction SilentlyContinue) { try { return "$(Get-PimFailureFixKind -Code $c)" } catch { } }
    return 'product-defect'
}

function Test-PimUplinkFixKindEnabled {
    <#
      100.34 (Invardia 2026-10-09: the §8.4 run report gets an optional FixKind, absent = product-defect). Invardia's side is
      LIVE (6f2dce4, migration 046: a customer-config report opens NO fix request, it shows as "Needs customer action"), so
      the field is ON by default from 2.4.539; PIM_UPLINK_FIXKIND = 0 / false / off / no switches it off (escape hatch).
      The class itself (ErrorClass) is sent either way.
    #>
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_FIXKIND)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

# ---------------------------------------------------------------------------------------------------------------------
# LANE repfix (owner's night order 2026-10-12): the ADDITIVE fields. PIM 100.99 / 100.111 Outcome + ActionBy, 100.115
# Solution, 100.103 Controls on the heartbeat, InstallRole / ManagingTenantId (agreed with Invardia 2026-10-12), and the
# updater's own run report. One switch for all of them: PIM_UPLINK_ADDITIVE = 0 / false / off / no sends the records exactly
# as before this lane. Invardia refuses a WHOLE report on one field it does not know, so a record that is refused as
# invalid is sent ONCE more in its old form, and the additive fields then stay off for 24 hours
# (UplinkState.additiveRefusedUtc) -- telemetry never goes silent because the platform is one release behind.
# ---------------------------------------------------------------------------------------------------------------------
function Test-PimUplinkAdditiveEnabled {
    <# PURE. ON by default; PIM_UPLINK_ADDITIVE = 0 / false / off / no switches every additive field off. #>
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_ADDITIVE)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function Test-PimUplinkAdditiveHeld {
    <# PURE. True while the additive fields are held back: Invardia refused them less than 24 hours ago. #>
    param([AllowNull()][object]$RefusedUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    $t = ConvertTo-PimUplinkUtc $RefusedUtc
    if (-not $t) { return $false }
    return (($NowUtc.ToUniversalTime() - $t).TotalHours -lt 24)   # literal: one retry a day
}

function Test-PimUplinkValidationRefusal {
    <# PURE. Did Invardia refuse the record's CONTENT (HTTP 400 / 422, "invalid", a field list)? A 401 / 403 / 429 / 5xx / no network is not that. #>
    param([AllowNull()][string]$Reason)
    $r = "$Reason"
    if (-not $r.Trim()) { return $false }
    if ($r -match '(?i)\b(401|403|429|5\d\d)\b|Too ?Many ?Requests|Unauthori[sz]ed|Forbidden') { return $false }
    return [bool]($r -match '(?i)\b(400|422)\b|Unprocessable|Bad ?Request|\binvalid\b|fields:')
}

# ---------------------------------------------------------------------------------------------------------------------
# 2.4.644 BUG "one refused field trips every hold" (live 2026-10-16 18:14:57Z on internal): a 422 naming ONLY SqlAccess.model
# also set the release-control and cause holds, because the first layer to see the refusal ($postRc) held its own group
# without asking WHICH field was refused. Invardia's 422 names its fields (the sender appends "[fields: a, b.c]"), so each
# hold now acts only on a named field of ITS group, and inside the additive group only the named top-level field(s) are
# dropped and held. A refusal that names nothing (an older Invardia, an unparsable answer) keeps the old fail-safe cascade.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimUplinkRefusedFields {
    <#
      PURE. The TOP-LEVEL record fields a refusal names: "...[fields: SqlAccess.model, Jobs[0].name, wave]" -> SqlAccess, Jobs,
      wave (unique, in order). A leading "$." / "/" (a JSON path / pointer) is ignored. Nothing named = an empty list.
    #>
    param([AllowNull()][string]$Reason)
    $out = New-Object System.Collections.Generic.List[string]
    # to the end of the line: a path may carry its own brackets (Jobs[0].name); text after the list ends the last name below
    $m = [regex]::Match("$Reason", '(?i)\bfields:\s*([^\r\n]*)')
    if (-not $m.Success) { return @() }
    foreach ($p in ($m.Groups[1].Value -split ',')) {
        $t = ("$p".Trim().Trim('"', "'", ' ', '[', '(', ')') -replace '^\$\.?', '') -replace '^/+', ''
        $top = ($t -split '[./\[\]\s"'')]', 2)[0].Trim()
        if ($top -match '^[A-Za-z_][A-Za-z0-9_]{0,63}$' -and -not ($out -contains $top)) { $out.Add($top) }
    }
    return @($out)
}

function Get-PimUplinkReleaseControlFieldNames { <# PURE. The release-control group (a literal). #> return @('wave', 'releaseMode') }
function Get-PimUplinkCauseFieldNames { <# PURE. The cause group (a literal). #> return @('Reports', 'Capabilities', 'Licences') }

function Resolve-PimUplinkRefusalSplit {
    <#
      PURE. Which hold(s) a refusal that NAMES its fields trips, and what to drop from the record:
        rc        a named field is wave / releaseMode                -> drop every release-control field on the record (-Rc)
        causes    a named field is Reports / Capabilities / Licences -> drop every cause field on the record (-Causes)
        additive  the named fields that are on the record's additive list (-Additive) -> drop ONLY those
      -> @{ named = <the refusal names fields>; act = <named AND something to drop>; rc; causes (bool); additive; drop; fields }
      act = $false means "do as before": the caller keeps the old fail-safe cascade (nothing named, or nothing it names is
      one of the record's optional fields -- e.g. a core field).
    #>
    param([AllowNull()][string]$Reason, [AllowNull()][object[]]$Additive = @(), [AllowNull()][object[]]$Causes = @(), [AllowNull()][object[]]$Rc = @(),
          [AllowNull()][object[]]$Fields = @())
    # the sender's Fields (Invardia's answer, Send-PimUplinkRecord) win; else the "[fields: ...]" of the reason text
    $fl = @(@($Fields) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $named = if ($fl.Count) { @(Get-PimUplinkRefusedFields -Reason "fields: $($fl -join ', ')") } else { @(Get-PimUplinkRefusedFields -Reason $Reason) }
    $o = @{ named = [bool]$named.Count; act = $false; rc = $false; causes = $false; additive = @(); drop = @(); fields = $named }
    if (-not $named.Count) { return $o }
    $rcG = @(Get-PimUplinkReleaseControlFieldNames); $cG = @(Get-PimUplinkCauseFieldNames)
    $o.rc = [bool](@($named | Where-Object { $rcG -contains $_ }).Count)
    $o.causes = [bool](@($named | Where-Object { $cG -contains $_ }).Count)
    # in the order Invardia named them, spelled as on the record
    $recAdd = @(@($Additive) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $add = @(foreach ($nf in $named) { $hit = @($recAdd | Where-Object { $_ -eq $nf }) | Select-Object -First 1; if ($hit) { "$hit" } })
    $o.additive = $add
    $drop = @()
    if ($o.rc) { $drop += @(@($Rc) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
    if ($o.causes) { $drop += @(@($Causes) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
    $drop += $add
    $o.drop = @($drop | Select-Object -Unique)
    $o.act = [bool]$o.drop.Count
    return $o
}

function ConvertTo-PimUplinkHeldFieldList {
    <# PURE. The stored per-field additive hold ("SqlAccess,Security" or a list) as a clean list of names; nothing = @(). #>
    param([AllowNull()][object]$Value)
    return @(@(@($Value) | ForEach-Object { "$_" -split ',' }) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]{0,63}$' } | Select-Object -Unique)
}

# ---------------------------------------------------------------------------------------------------------------------
# §33.0 BUG (2026-10-16: internal held the cause fields from 2026-10-15 23:39Z and NOTHING said which record was refused or
# why -- no run message, no console line, and Invardia keeps no refused bodies). Each of the three holds (additive / cause /
# release-control) now records WHAT was refused beside its ...RefusedUtc: the record kind, the job (a run) or the guard id,
# the HTTP status and Invardia's answer (scrubbed, at most 1000). One Write-Warning names it; the run message names it, and
# every later cycle while the hold lasts says so. Additive and fail-safe: a failure here never stops a record or a hold.
# ---------------------------------------------------------------------------------------------------------------------
function New-PimUplinkRefusalInfo {
    <#
      PURE. What Invardia refused: @{ utc; kind; job; status; reason } from the refused record and the sender's -Reason.
        kind    the record's Kind (heartbeat | run | guard | setup ...; a guard 'cleared' record = guard-cleared), else 'record'
        job     a run's Job, a guard's GuardId, else ''
        status  the HTTP status in the reason (422, 400 ...), 0 when it names none
        reason  the answer, secrets scrubbed (-AccessCode, an install key, a bearer token / JWT; the framework redact), <= 1000
    #>
    param([AllowNull()][object]$Record, [AllowNull()][string]$Reason, [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()][string]$AccessCode = '')
    $kind = ("$(Get-PimUplinkField $Record 'Kind')".Trim().ToLowerInvariant() -replace '[^a-z0-9-]+', '-').Trim('-')
    if (-not $kind) { $kind = 'record' }
    if ($kind -eq 'guard' -and "$(Get-PimUplinkField $Record 'GuardOutcome')" -eq 'cleared') { $kind = 'guard-cleared' }
    $job = "$(Get-PimUplinkField $Record 'Job')".Trim()
    if (-not $job -and $kind -like 'guard*') { $job = "$(Get-PimUplinkField $Record 'GuardId')".Trim() }
    if ($job.Length -gt 80) { $job = $job.Substring(0, 80) }
    $r = "$Reason".Trim()
    $status = 0
    if ($r -match '\((\d{3})\)') { $status = [int]$Matches[1] }                                   # 5.1: "(422) Unprocessable Entity"
    elseif ($r -match '(?i)status code[^0-9]{0,40}(\d{3})\b') { $status = [int]$Matches[1] }      # 7: "status code does not indicate success: 422"
    elseif ($r -match '\b([45]\d\d)\b') { $status = [int]$Matches[1] }
    if ("$AccessCode".Trim()) { $r = $r.Replace("$AccessCode".Trim(), '***') }
    $r = $r -replace '(?i)\binv-[a-z0-9]{12,}', 'inv-***' -replace '(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer ***' -replace 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', '***'
    if (Get-Command ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { try { $r = "$(ConvertTo-AitUplinkRedacted -Text $r)" } catch { } }
    if ($r.Length -gt 1000) { $r = $r.Substring(0, 997) + '...' }
    return [ordered]@{ utc = $NowUtc.ToUniversalTime().ToString('o'); kind = $kind; job = $job; status = $status; reason = $r }
}

function Format-PimUplinkRefusalLine {
    <# PURE. The one sentence that names a refusal: "Invardia refused the <what> on a <kind> record (job x): HTTP 422 -- <reason>". #>
    param([string]$What, [AllowNull()][object]$Info)
    if ($null -eq $Info) { return "Invardia refused the $What" }
    $j = "$(Get-PimUplinkField $Info 'job')"; $s = "$(Get-PimUplinkField $Info 'status')"; $why = "$(Get-PimUplinkField $Info 'reason')"
    return ("Invardia refused the {0} on a {1} record{2}: {3}{4}" -f $What, "$(Get-PimUplinkField $Info 'kind')", $(if ($j) { " (job $j)" } else { '' }),
            $(if ($s -and $s -ne '0') { "HTTP $s" } else { 'no HTTP status' }), $(if ($why) { " -- $why" } else { '' }))
}

function Set-PimUplinkRefusalState {
    <#
      The ...RefusedKind / ...RefusedJob / ...RefusedStatus / ...RefusedReason of one hold (-Prefix 'causesRefused' etc.) into the
      new UplinkState: this cycle's refusal (-Info), else -- while the hold lasts (-Carry) -- the previous state's values, so the
      reason stays readable for the whole 24 h. Nothing is written while the hold was never set (the state stays as before).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)][string]$Prefix, [AllowNull()][object]$Info,
          [AllowNull()][object]$Previous, [bool]$Carry = $false)
    $map = [ordered]@{ Kind = 'kind'; Job = 'job'; Status = 'status'; Reason = 'reason' }
    foreach ($k in $map.Keys) {
        $n = "$Prefix$k"
        if ($null -ne $Info) { $State[$n] = Get-PimUplinkField $Info $map[$k] }
        elseif ($Carry -and $null -ne $Previous) { $pv = Get-PimUplinkField $Previous $n; if ($null -ne $pv) { $State[$n] = $pv } }
    }
}

function Format-PimUplinkHeldNote {
    <#
      PURE. While a hold lasts (not refused THIS cycle): "; the <what> are held until <utc> (Invardia refused them <utc> on a
      <kind> record (job x): HTTP 422)" -- from the stored state (-Prefix), so every uplink run of the 24 h says it, whichever
      caller set it (the hourly job, the alert flush before a customer mail). A hold stored before this build has no reason.
    #>
    param([string]$What, [string]$Prefix, [AllowNull()][object]$State, [AllowNull()][object]$RefusedUtc)
    $t = ConvertTo-PimUplinkUtc $RefusedUtc
    if (-not $t) { return '' }
    $until = $t.AddHours(24).ToString('yyyy-MM-dd HH:mm') + 'Z'; $at = $t.ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
    $kind = "$(Get-PimUplinkField $State "${Prefix}Kind")"
    if (-not $kind) { return "; the $What are held until $until (Invardia refused them at $at; what was refused was not recorded)" }
    $j = "$(Get-PimUplinkField $State "${Prefix}Job")"; $s = "$(Get-PimUplinkField $State "${Prefix}Status")"
    return "; the $What are held until $until (Invardia refused them at $at on a $kind record$(if ($j) { " (job $j)" }): $(if ($s -and $s -ne '0') { "HTTP $s" } else { 'no HTTP status' }))"
}

function Get-PimUplinkFailureCodes {
    <#
      PURE. The catalog classes a failed run's text names AS FAILURES, largest group first (the order of the text):
      the bracketed codes of the "N item(s) failed: ..." part. The "WAITING" and "NEEDS APPROVAL" parts are cut off first
      (those items are not failures), a bracketed word that is not a catalog class is ignored, UNCLASSIFIED is kept.
    #>
    param([string]$Text)
    $t = "$Text"
    if (-not $t.Trim()) { return @() }
    foreach ($cut in @('\d+ item\(s\) WAITING', '(ALSO )?NEEDS APPROVAL')) {
        $m = [regex]::Match($t, $cut)
        if ($m.Success) { $t = $t.Substring(0, $m.Index) }
    }
    $known = @{}
    if (Get-Command Get-PimFailureCatalogCodes -ErrorAction SilentlyContinue) { try { foreach ($c in @(Get-PimFailureCatalogCodes)) { $known["$c"] = $true } } catch { } }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($t, '\[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)\]')) {
        $code = $m.Groups[1].Value
        if ($known.ContainsKey($code) -and -not $out.Contains($code)) { $out.Add($code) }
    }
    return $out.ToArray()
}

function Get-PimUplinkOutcomeAction {
    <#
      PURE. PIM 100.99 / 100.111 -- the owner's closed list at Invardia (Error / Needs customer's action / Warning / Held
      back / OK / Not checked) as two fields on every run report:
        Outcome   ok | warning | held | failed          ActionBy   customer | product-team | none | unknown
      THE RULES (from what the run already says about itself; nothing is read):
        ok                                                   -> ok      / none
        Microsoft throttled it, or the run was interrupted   -> warning / none          (retried by itself)
        a safety check held a change set (held run)          -> held    / customer      (an approver of the tenant decides)
        the run declared a warning about itself              -> warning / customer when its kind starts with 'customer', else unknown
        FAILED, and its text names failure classes:
          every class is a hold (REMOVE-BUDGET-HELD, *-MASS-HOLD)             -> held    / customer
          every class is customer-config, and one of those items is a REMOVAL
          that did not happen (-NotRemoved: the access is still there)         -> failed  / customer   (stays red)
          every class is customer-config AND the text is an item summary
          ("N item(s) failed: ...") or a customer-configuration convergence   -> warning / customer   (the job did its work)
          every class is customer-config, the job itself stopped on it        -> failed  / customer
          any class is a product fault                                         -> failed  / product-team
          else (UNCLASSIFIED among them)                                       -> failed  / unknown
        FAILED without a named class: the class of the raw text decides -- customer-config -> failed / customer,
          UNCLASSIFIED / none -> failed / unknown, anything else -> failed / product-team.
      failed = the job could not do its work. held is never a failure. Returns @{ outcome; actionBy; codes }.
      NOT decided by the owner, so NOT built: "more than a share of a scope's items = failed" and the repeat after N days.
    #>
    param([string]$LegacyOutcome = 'ok', [string]$Kind = '', [string]$Text = '', [string]$ErrorClass = '', [string]$WarningKind = '',
          # how many currently-failing items of the run's classes are REMOVALS (op Remove in 'EngineItemFailures')
          [int]$NotRemoved = 0)
    $lo = "$LegacyOutcome".Trim().ToLowerInvariant(); $k = "$Kind".Trim().ToLowerInvariant()
    $r = [ordered]@{ outcome = 'ok'; actionBy = 'none'; codes = @() }
    if ($lo -eq 'ok' -or -not $lo) { return [pscustomobject]$r }
    if ($lo -eq 'warning') {
        $r.outcome = 'warning'
        if ($k -eq 'held') { $r.outcome = 'held'; $r.actionBy = 'customer' }
        elseif ($k -eq 'warning') { $r.actionBy = $(if ("$WarningKind".Trim() -match '^(?i)customer') { 'customer' } else { 'unknown' }) }
        elseif ($k -in @('throttled', 'interrupted')) { $r.actionBy = 'none' }
        else { $r.actionBy = 'unknown' }
        return [pscustomobject]$r
    }
    $r.outcome = 'failed'; $r.actionBy = 'unknown'
    $codes = @(Get-PimUplinkFailureCodes -Text $Text)
    $r.codes = $codes
    if ($codes.Count) {
        $kinds = @($codes | ForEach-Object { if ("$_" -eq 'UNCLASSIFIED') { 'unknown' } else { Get-PimUplinkFixKind -ErrorClass "$_" } })
        $allCustomer = (@($kinds | Where-Object { $_ -ne 'customer-config' }).Count -eq 0)
        if ($allCustomer) {
            $r.actionBy = 'customer'
            $allHold = (@($codes | Where-Object { "$_" -ne 'REMOVE-BUDGET-HELD' -and "$_" -notmatch '-MASS-HOLD$' }).Count -eq 0)
            if ($allHold) { $r.outcome = 'held' }
            # the owner's condition (100.99): a REMOVAL that did not happen -- the access is still there -- stays failed
            elseif ($NotRemoved -gt 0) { $r.outcome = 'failed' }
            elseif ("$Text" -match '\d+ item\(s\) failed:' -or "$Text" -match '(?i)CONVERGENCE FAILURE \(customer configuration\)') { $r.outcome = 'warning' }
        }
        elseif (@($kinds | Where-Object { $_ -eq 'product-defect' }).Count) { $r.actionBy = 'product-team' }
        return [pscustomobject]$r
    }
    $cls = "$ErrorClass".Trim().ToUpperInvariant()
    if (-not $cls -or $cls -eq 'UNCLASSIFIED') { return [pscustomobject]$r }
    $r.actionBy = $(if ((Get-PimUplinkFixKind -ErrorClass $cls) -eq 'customer-config') { 'customer' } else { 'product-team' })
    return [pscustomobject]$r
}

function Get-PimUplinkGuardOutcomeAction {
    <#
      PURE. PIM 100.99 / 100.111 for a GUARD record, from its own GuardOutcome and Action text (nothing else is known):
        cleared                              -> ok      / none
        halted | refused | held | skipped    -> held    / customer   (a safety check paused a change on purpose; a person in
                                                                     the tenant reviews, approves or releases it)
        warning                              -> warning / unknown
      An Action text that starts with "Nothing to do" makes ActionBy 'none' (PIM 100.104: the text starts with who acts).
      A guard is never 'failed'. Returns @{ outcome; actionBy }.
    #>
    param([string]$GuardOutcome = '', [string]$ActionText = '')
    $g = "$GuardOutcome".Trim().ToLowerInvariant()
    if ($g -eq 'cleared') { return [pscustomobject]@{ outcome = 'ok'; actionBy = 'none' } }
    $o = 'warning'; $a = 'unknown'
    if ($g -in @('halted', 'refused', 'held', 'skipped')) { $o = 'held'; $a = 'customer' }
    if ("$ActionText".Trim() -match '^(?i)nothing to do\b') { $a = 'none' }
    return [pscustomobject]@{ outcome = $o; actionBy = $a }
}

function Get-PimUplinkInstallRole {
    <#
      PURE. The heartbeat's InstallRole (agreed with Invardia 2026-10-12): single | managing | managed, from the product's
      OWN scenario role (PIM-ScenarioProfile.ps1: 'single', 'msp-master', 'msp-managed'). Any other / no role = '' -- the
      field is then LEFT OUT (never guessed). ManagingTenantId only for a managed installation, only when it is a GUID and
      not this tenant's own id. Returns @{ role; managingTenantId }.
    #>
    param([AllowNull()][string]$ScenarioRole, [AllowNull()][string]$ManagingTenantId = '', [AllowNull()][string]$TenantId = '')
    $role = ''
    switch ("$ScenarioRole".Trim().ToLowerInvariant()) {
        'single'      { $role = 'single' }
        'msp-master'  { $role = 'managing' }
        'msp-managed' { $role = 'managed' }
    }
    $mt = ''
    if ($role -eq 'managed') {
        $c = "$ManagingTenantId".Trim().Trim('"').ToLowerInvariant()
        if ($c -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' -and $c -ne "$TenantId".Trim().ToLowerInvariant()) { $mt = $c }
    }
    return [pscustomobject]@{ role = $role; managingTenantId = $mt }
}

function Resolve-PimUplinkScenarioRole {
    <#
      The product's own role for InstallRole: the STORED scenario (pim.Settings 'Scenario', read through -GetSetting: an id,
      or { scenario: <id> }) resolved by the product's scenario table (Get-PimScenario -> role 'single' | 'msp-master' |
      'msp-managed'). '' when nothing is stored, the id is not a supported scenario, the table is not loaded or the read
      threw -- Get-PimActiveScenario's "safest default: single tenant" is a default to RUN with, not a fact to REPORT.
      -Lookup { param($Id) } is the test seam (default: Get-PimScenario). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [scriptblock]$Lookup = $null)
    try {
        $raw = & $GetSetting 'Scenario'
        $id = ''
        if ($raw -is [string]) {
            $t = $raw.Trim().Trim('"')
            if ($t.StartsWith('{')) { try { $id = "$(Get-PimUplinkField ($t | ConvertFrom-Json) 'scenario')" } catch { $id = '' } } else { $id = $t }
        } elseif ($null -ne $raw) { $id = "$(Get-PimUplinkField $raw 'scenario')" }
        $id = "$id".Trim()
        if (-not $id) { return '' }
        $sc = $null
        if ($Lookup) { $sc = & $Lookup $id }
        elseif (Get-Command Get-PimScenario -ErrorAction SilentlyContinue) { $sc = Get-PimScenario -Id $id }
        if ($null -eq $sc) { return '' }
        return "$(Get-PimUplinkField $sc 'role')".Trim().ToLowerInvariant()
    } catch { return '' }
}

function ConvertTo-PimUplinkHeartbeatControls {
    <#
      PURE. PIM 100.103 (owner 2026-10-12: "an unknown status which is yellow is bad" / "telemetry must include this more
      frequent"). The setup controls for the IDENTIFIED heartbeat: EVERY declared control (the same list and the same
      evaluation as the Kind=setup report -- Get-PimSetupControlCatalog / Get-PimSetupControlStates), each
        { id; state ok|missing|wrong|unknown; value? (enum controls only); checkedUtc; reason? (unknown only:
          not-due-yet | no-recent-check | not-readable | not-applicable) }.
      A control the evaluation did not return is 'unknown' / 'not-readable' (never left out). Empty when the setup library
      is not loaded or the facts are missing -- the heartbeat then carries no Controls.
    #>
    param([AllowNull()][object]$Facts, [switch]$Extended, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Facts -or -not (Get-Command Get-PimSetupControlStates -ErrorAction SilentlyContinue)) { return $out.ToArray() }
    try {
        $nowText = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $got = @{}; foreach ($c in @(Get-PimSetupControlStates -Facts $Facts -Extended:$Extended)) { if ($c) { $got["$($c.id)"] = $c } }
        foreach ($c in @(Get-PimSetupControlCatalog -Extended:$Extended)) {
            $e = $got["$($c.id)"]
            $state = 'unknown'; if ($e -and "$($e.state)" -in @('ok', 'missing', 'wrong', 'unknown')) { $state = "$($e.state)" }
            $o = [ordered]@{ id = "$($c.id)"; state = $state }
            if ($e -and $c.Contains('enum') -and (@($c.enum) -contains "$(Get-PimUplinkField $e 'value')")) { $o['value'] = "$(Get-PimUplinkField $e 'value')" }
            $ck = "$(Get-PimUplinkField $e 'checkedUtc')".Trim()
            $o['checkedUtc'] = $(if ($ck -match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$') { $ck } else { $nowText })
            if ($state -eq 'unknown') {
                $rs = "$(Get-PimUplinkField $e 'reason')".Trim().ToLowerInvariant()
                if ($rs -notin @('not-due-yet', 'no-recent-check', 'not-readable', 'not-applicable')) { $rs = 'not-readable' }
                $o['reason'] = $rs
            }
            $out.Add([pscustomobject]$o)
        }
    } catch { return @() }
    # Unrolled on purpose (like Select-PimUplinkEndpoints): every caller wraps the call in @().
    return $out.ToArray()
}

function ConvertTo-PimUplinkUpdateRun {
    <#
      PURE. PIM 100.103 (b): the updater records EVERY run -- also "nothing to do" -- in pim.Settings 'UpdateState'
      (update-job-entry.ps1 Send-PimUpdateOutcome, kind 'run'). This turns that record into a run the plan reports as job
      'pim-update' (ONE report per updater run: the plan's per-job watermark is the record's own time):
        outcome ok / ahead                      -> completed          failed -> failed (with its error text)
        attention / waiting / skipped           -> a warning the run declared about itself (kind 'customer': the text says
                                                   what the operator of the environment decides)
      updateAction = none | built | rolled | schema | failed ('none' = nothing to do). $null when there is no run record
      (a deploy record only), no time, or an outcome outside the list.
    #>
    param([AllowNull()][object]$UpdateState)
    try {
        if ($null -eq $UpdateState) { return $null }
        if ("$(Get-PimUplinkField $UpdateState 'kind')".Trim().ToLowerInvariant() -ne 'run') { return $null }
        $ts = ConvertTo-PimUplinkUtc (Get-PimUplinkField $UpdateState 'tsUtc')
        if (-not $ts) { return $null }
        $oc = "$(Get-PimUplinkField $UpdateState 'outcome')".Trim().ToLowerInvariant()
        $act = "$(Get-PimUplinkField $UpdateState 'action')".Trim().ToLowerInvariant()
        if ($act -notin @('none', 'built', 'rolled', 'schema', 'failed')) { $act = '' }
        $err = "$(Get-PimUplinkField $UpdateState 'error')".Trim()
        $dur = 0; [void][int]::TryParse("$(Get-PimUplinkField $UpdateState 'durationSec')", [ref]$dur)
        $status = ''; $ok = $true; $warn = $false
        if ($oc -in @('ok', 'ahead')) { $status = 'completed' }
        elseif ($oc -eq 'failed') { $status = 'failed'; $ok = $false }
        elseif ($oc -in @('attention', 'waiting', 'skipped')) { $status = 'warning'; $warn = $true }
        else { return $null }
        $detail = $err
        if (-not $detail -and $status -eq 'completed') { $detail = $(if ($act -eq 'none' -or -not $act) { 'update: nothing to do' } else { "update: $act" }) }
        return [pscustomobject]@{ name = 'update'; type = 'update'; status = $status; ok = $ok; held = $false; warning = $warn
            warningKind = $(if ($warn) { 'customer-update' } else { '' }); warningSummary = $(if ($warn) { $err } else { '' })
            detail = $detail; durationMs = ([int64]$dur * 1000); finishedUtc = $ts.ToString('o'); updateAction = $act }
    } catch { return $null }
}

function Get-PimUplinkConsentAction {
    <#
      PURE. Invardia PRO-UPDATE-PLATFORM §11: ONE report when the customer switches telemetry off ('optout'), ONE when it is
      switched on again ('optin'). -State = UplinkState; its 'consent' is the last switch position that was DELIVERED
      ('on' / 'off'). A state written before consent existed, by a cycle that sent, counts as 'on'.
        on  -> off  : 'optout'      off -> on : 'optin'
        never on, off : ''  -- nothing was ever sent, so there is nothing to opt out of (no call to invardia.com at all)
        first time on : ''  -- starting is not an opt-in
    #>
    param([AllowNull()][object]$State, [bool]$Enabled)
    $prev = ''
    if ($State) {
        if ($State.PSObject.Properties['consent'] -and "$($State.consent)".Trim()) { $prev = "$($State.consent)".Trim().ToLowerInvariant() }
        elseif ($State.PSObject.Properties['mode'] -and "$($State.mode)" -in @('anonymous', 'identified')) { $prev = 'on' }
    }
    if ($Enabled -and $prev -eq 'off') { return 'optin' }
    if (-not $Enabled -and $prev -eq 'on') { return 'optout' }
    return ''
}

function New-PimUplinkConsentReport {
    <#
      PURE. The optout / optin record: Schema 2, the Kind and the identity fields only (Product, Version, Ring, and the
      InstallId when anonymous / ClaimedTenantId when identified). Built HERE, not by the framework's New-AitUplinkReport,
      whose Kind list is heartbeat / run / install: sync/ ships to every customer with release discipline, and PIM's copy of
      it must stay byte-identical (Test-PimUplink). Invardia's server lists both kinds (packages/core uplink.ts KINDS).
      $null when an anonymous report has no install id (the server would refuse it).
    #>
    param([Parameter(Mandatory)][ValidateSet('optout', 'optin')][string]$Kind, [Parameter(Mandatory)][ValidateSet('anonymous', 'identified')][string]$Mode,
          [string]$Version = '', [AllowNull()][object]$Ring, [string]$InstallId = '', [string]$TenantId = '', [datetime]$Now = [datetime]::UtcNow)
    $iid = "$InstallId".Trim().ToLowerInvariant()
    if ($Mode -eq 'anonymous' -and $iid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $null }
    $o = [ordered]@{ Schema = 2; Kind = $Kind; Product = $script:PimUplinkProduct }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    if ($Mode -eq 'anonymous') { $o['InstallId'] = $iid } elseif ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() }
    $o['LastSeenUtc'] = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    return [pscustomobject]$o
}

# PIM 100.36 (owner via Invardia 2026-10-09: "telemetry must collect available sql db space remaining in health telemetry"):
# allocated data pages (ROWS files) and the database's max size, both MB. Azure SQL; on a server without a max size
# (MaxSizeInBytes NULL / -1) nothing is reported.
$script:PimUplinkSqlSpaceQuery = @'
SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS bigint) / 1048576 AS maxMb,
       (SELECT SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint)) * 8 / 1024 FROM sys.database_files WHERE type_desc = 'ROWS') AS usedMb
'@

function Get-PimUplinkSqlSpace {
    <#
      PIM 100.36. The heartbeat's SQL space numbers: @{ sqlUsedMb; sqlMaxMb } (integers, MB), or $null. -Query { } runs the SQL
      above and returns its row (the job binds Invoke-PimSqlQuery with the store's MI connection; tests pass a stub). A query
      that throws, returns nothing, or a value that is missing / not a number / not positive (max) = $null: BOTH keys are
      then left out -- never a 0, never a guess. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query)
    try {
        $row = @(& $Query) | Select-Object -First 1
        if ($null -eq $row) { return $null }
        $u = Get-PimUplinkField $row 'usedMb'; $m = Get-PimUplinkField $row 'maxMb'
        $ui = [int64]0; $mi = [int64]0
        if ($null -eq $u -or $null -eq $m -or $u -is [DBNull] -or $m -is [DBNull]) { return $null }
        if (-not [int64]::TryParse("$u", [ref]$ui) -or -not [int64]::TryParse("$m", [ref]$mi)) { return $null }
        if ($ui -lt 0 -or $mi -le 0) { return $null }
        return @{ sqlUsedMb = $ui; sqlMaxMb = $mi }
    } catch { return $null }
}

# PIM 100.128 (owner via Invardia 2026-10-13: "selling points of adoption") -- the ADOPTION counts of the IDENTIFIED heartbeat,
# for Invardia's back-office dashboard. Whole numbers per install, from PIM's OWN SQL store only (no Graph / ARM read), one
# scalar COUNT per key, computed only when a heartbeat is due (hourly). A key whose source cannot be read (the query throws,
# the table is not there, the result is NULL / not a number / negative) is LEFT OUT -- never a 0. Anonymous mode sends none.
# The heartbeat's other keys (sqlUsedMb, sqlMaxMb, users, guests, servicePrincipals, groups, usersTotal, usersDisabled = 8)
# plus these 13 = 21, under the framework's 40-key cap (sync/_AitUplink.ps1).
# §33.0 MORE TELEMETRY (owner 2026-10-16 via Invardia: "add relevant. i want data"; Invardia accepted the flat keys the same
# day): 12 more -- activity (activations24h / 7d, approvalsPending), standing access (permanentPrivilegedAssignments,
# permanentGlobalAdmins, privilegedGuests, privilegedSpns, roleAssignmentsOutsidePim), hygiene (assignmentsExpiring7d) and
# drift / convergence (driftItems, unconvergedItems, convergenceFailures24h) = 33. Same rule: unreadable = left out, never 0.
# The 40-key ceiling is guarded IN CODE before the record is built (Limit-PimUplinkCounts).
function Get-PimUplinkAdoptionCountKeys {
    <# PURE. Every adoption key, in the order the heartbeat builds them (a literal: child-scope safe). #>
    return @('managedAdmins', 'managedGroups', 'delegations', 'privilegedRoles', 'eligibleAssignments', 'activeAssignments',
             'azureRoleAssignments', 'activations30d', 'approvals30d', 'accessReviewsCompleted30d', 'managedTenants',
             'hybridAdGroups', 'hybridServers',
             'activations24h', 'activations7d', 'approvalsPending', 'permanentPrivilegedAssignments', 'permanentGlobalAdmins',
             'privilegedGuests', 'privilegedSpns', 'roleAssignmentsOutsidePim', 'assignmentsExpiring7d', 'driftItems',
             'unconvergedItems', 'convergenceFailures24h')
}

function Get-PimUplinkCountsKeyMax {
    <# PURE. Invardia refuses a WHOLE record whose Counts has more than 40 keys (agreed SI + PIM + Invardia 2026-10-13). A literal. #>
    return 40
}

function Get-PimUplinkCountsPriority {
    <#
      PURE. Every Counts key the heartbeat may carry, MOST important first (a literal: child-scope safe). Above the cap the
      keys at the END go first; a key not in this list ranks below every listed key (alphabetical among themselves).
    #>
    return @('sqlUsedMb', 'sqlMaxMb', 'users', 'guests', 'servicePrincipals', 'groups', 'usersTotal', 'usersDisabled') + @(Get-PimUplinkAdoptionCountKeys)
}

function Limit-PimUplinkCounts {
    <#
      The HARD CAP: a Counts map with at most Get-PimUplinkCountsKeyMax keys. Above it the lowest-priority keys
      (Get-PimUplinkCountsPriority, unknown keys last, then alphabetical) are dropped -- deterministic, the same keys every
      heartbeat -- and ONE Write-Warning names them. $null / empty in = the same out. Never throws.
    #>
    [CmdletBinding()] param([AllowNull()][hashtable]$Counts)
    if ($null -eq $Counts -or $Counts.Count -eq 0) { return $Counts }
    $max = Get-PimUplinkCountsKeyMax
    if ($Counts.Count -le $max) { return $Counts }
    try {
        $prio = @(Get-PimUplinkCountsPriority)
        $rank = @{}; for ($i = 0; $i -lt $prio.Count; $i++) { if (-not $rank.ContainsKey($prio[$i])) { $rank[$prio[$i]] = $i } }
        $ordered = @(@($Counts.Keys) | Sort-Object @{ Expression = { if ($rank.ContainsKey("$_")) { [int]$rank["$_"] } else { [int]::MaxValue } } }, @{ Expression = { "$_" } })
        $keep = @($ordered | Select-Object -First $max)
        $drop = @($ordered | Select-Object -Skip $max)
        $out = @{}; foreach ($k in $keep) { $out["$k"] = $Counts[$k] }
        Write-Warning ("[uplink] the heartbeat's Counts had {0} keys, more than Invardia accepts ({1}) -- left out: {2}" -f $Counts.Count, $max, ($drop -join ', '))
        return $out
    } catch {
        $out = @{}; foreach ($k in @(@($Counts.Keys) | Sort-Object | Select-Object -First $max)) { $out["$k"] = $Counts[$k] }
        return $out
    }
}

function Get-PimUplinkSettingJsonSql {
    <#
      PURE. A T-SQL prelude that reads pim.Settings[<Name>] into @v (JSON text) and @has (1 = the row exists). A value stored
      DOUBLE-encoded (a JSON string whose text is the JSON -- Set-PimSetting with pre-serialised text: ConvergenceState,
      ApprovalRequests, legacy JobRunHistory) is decoded once, inside SQL. Nothing leaves SQL but the caller's scalar.
    #>
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9.]+$')][string]$Name)
    return "DECLARE @has BIT = CASE WHEN EXISTS (SELECT 1 FROM pim.Settings WHERE Name = N'$Name') THEN 1 ELSE 0 END; DECLARE @v NVARCHAR(MAX) = (SELECT ValueJson FROM pim.Settings WHERE Name = N'$Name'); IF @v IS NOT NULL AND ISJSON(@v) = 0 AND ISJSON(N'[' + @v + N']') = 1 SET @v = (SELECT TOP 1 [value] FROM OPENJSON(N'[' + @v + N']') WHERE [type] = 1);"
}

function Get-PimUplinkConvergenceFailures {
    <#
      PURE. convergenceFailures24h: FAILED verify-convergence runs (Get-PimUplinkRunOutcome = failed: an interrupted or
      throttled run is not one) that finished in the last 24 hours, from the job run history. NOTE the history keeps the
      newest 10 runs per job (PimRunHistoryMax), so at the job's 30-minute cadence this sees ~5 hours at most.
    #>
    param([AllowNull()][object[]]$Runs, [datetime]$NowUtc = [datetime]::UtcNow)
    $cut = $NowUtc.ToUniversalTime().AddHours(-24)
    $n = 0
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $t = "$($r.type)".Trim().ToLowerInvariant(); if (-not $t) { $t = "$($r.name)".Trim().ToLowerInvariant() }
        if ($t -ne 'verify-convergence') { continue }
        $fin = ConvertTo-PimUplinkUtc $r.finishedUtc
        if (-not $fin -or $fin -lt $cut) { continue }
        if ((Get-PimUplinkRunOutcome -Run $r) -eq 'failed') { $n++ }
    }
    return [long]$n
}

function Get-PimUplinkAdoptionQueries {
    <#
      PURE. key -> one scalar SQL statement (column n). -MspMaster adds managedTenants (a managing install's registry);
      -HybridAd adds hybridAdGroups + hybridServers (the hybrid worker's own records). Every JSON read is guarded by ISJSON
      (JSON_VALUE over text that is not JSON throws, and SQL Server does not promise to short-circuit an AND). A source that
      exists but holds nothing answers NULL where "nothing recorded" is not the same as "none" (no complete active-assignments
      snapshot, no hybrid-worker record) -- NULL = the key is left out.
    #>
    param([switch]$MspMaster, [switch]$HybridAd)
    $j = { param($p) "CASE WHEN ISJSON(DataJson) = 1 THEN LTRIM(RTRIM(JSON_VALUE(DataJson, '$.$p'))) END" }
    $defs = "N'PIM-Definitions-Roles', N'PIM-Definitions-Services', N'PIM-Definitions-Organization', N'PIM-Definitions-Tasks', N'PIM-Definitions-Departments', N'PIM-Definitions-Processes', N'PIM-Definitions-Projects', N'PIM-Definitions-CrossOrg'"
    $snap = "(SELECT MAX(SnapshotId) FROM pim.ActiveAssignmentSnapshots WHERE State = N'complete')"
    $q = [ordered]@{
        # admin rows defined in PIM (Account-Definitions-Admins), not AccountStatus = Deleted
        managedAdmins        = "SELECT COUNT_BIG(*) AS n FROM pim.Rows WHERE Entity = N'Account-Definitions-Admins' AND UPPER(ISNULL($(& $j 'AccountStatus'), N'')) <> N'DELETED'"
        # PIM groups defined (the eight group-definition entities, by GroupName, retired groups excluded) -- the engine's own list
        managedGroups        = "SELECT COUNT_BIG(DISTINCT LOWER(g)) AS n FROM (SELECT $(& $j 'GroupName') AS g, $(& $j 'Lifecycle') AS l FROM pim.Rows WHERE Entity IN ($defs)) x WHERE ISNULL(g, N'') <> N'' AND LOWER(ISNULL(l, N'')) NOT LIKE N'retire%'"
        # delegation rows of every kind (PIM-Assignments-*), not Action = Remove
        delegations          = "SELECT COUNT_BIG(*) AS n FROM pim.Rows WHERE Entity LIKE N'PIM-Assignments-%' AND UPPER(ISNULL($(& $j 'Action'), N'')) <> N'REMOVE'"
        # distinct Entra roles that a (non-Remove) delegation row grants: role -> group, role -> group in an AU, role -> user
        privilegedRoles      = "SELECT COUNT_BIG(DISTINCT LOWER(r)) AS n FROM (SELECT COALESCE(NULLIF($(& $j 'RoleDefinitionName'), N''), $(& $j 'RoleName')) AS r, $(& $j 'Action') AS a FROM pim.Rows WHERE Entity IN (N'PIM-Assignments-Roles-Groups', N'PIM-Assignments-Roles-AUs', N'PIM-Assignments-Roles-Direct')) x WHERE ISNULL(r, N'') <> N'' AND UPPER(ISNULL(a, N'')) <> N'REMOVE'"
        # eligible assignments PIM manages, confirmed in the tenant by the engine (the active-assignments read holds ACTIVE ones only)
        eligibleAssignments  = "SELECT COUNT_BIG(*) AS n FROM pim.ManagedKeys WHERE [Key] LIKE N'%|eligible'"
        # every active assignment of the last complete tenant-wide read (Entra roles + Azure RBAC + PIM for Groups)
        activeAssignments    = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap) END AS n"
        azureRoleAssignments = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND Kind = N'azure-rbac') END AS n"
        # the activation ledger (pim.ImpactActivations: every time-bound active assignment the snapshot job saw, once) -- by start
        activations30d       = "SELECT COUNT_BIG(*) AS n FROM pim.ImpactActivations WHERE StartUtc >= DATEADD(day, -30, SYSUTCDATETIME())"
        # approval decisions in the audit trail (approved / denied requests, approved mass-change holds) -- the Dashboard's rule
        approvals30d         = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE Ts >= DATEADD(day, -30, SYSUTCDATETIME()) AND (Action IN (N'approval.request.approved', N'approval.request.denied') OR Action LIKE N'%.policy.masschange.approved')"
        # review decisions in the audit trail (access-review decision, company-review answer, owner keep / remove / extend)
        accessReviewsCompleted30d = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE Ts >= DATEADD(day, -30, SYSUTCDATETIME()) AND Action IN (N'access-review.decision', N'company-review.answer', N'owner.keep', N'owner.remove', N'owner.extend')"
        # §33.0 MORE TELEMETRY -- the activation ledger by start, the last day / week
        activations24h       = "SELECT COUNT_BIG(*) AS n FROM pim.ImpactActivations WHERE StartUtc >= DATEADD(hour, -24, SYSUTCDATETIME())"
        activations7d        = "SELECT COUNT_BIG(*) AS n FROM pim.ImpactActivations WHERE StartUtc >= DATEADD(day, -7, SYSUTCDATETIME())"
        # PIM's own maker / checker queue (pim.Settings 'ApprovalRequests', a JSON array; status Pending). No row = an empty
        # queue (Get-PimApprovalRequests reads it the same way); a value that is not JSON = left out.
        approvalsPending     = "$(Get-PimUplinkSettingJsonSql -Name 'ApprovalRequests') SELECT CASE WHEN @v IS NULL THEN CAST(0 AS bigint) WHEN ISJSON(@v) = 0 THEN NULL ELSE (SELECT COUNT_BIG(*) FROM OPENJSON(@v) j WHERE j.[type] = 5 AND UPPER(ISNULL(CASE WHEN j.[type] = 5 THEN JSON_VALUE(j.[value], '$.status') END, N'')) = N'PENDING') END AS n"
        # standing access from the last COMPLETE active-assignments snapshot: Entra role assignments with no end date
        permanentPrivilegedAssignments = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND Kind = N'entra-role' AND EndUtc IS NULL) END AS n"
        # ... of the Global Administrator role (template id 62e90394-...): the row's managed identity r|<principal>|<role>|<scope>
        permanentGlobalAdmins = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND Kind = N'entra-role' AND EndUtc IS NULL AND IdentityKey LIKE N'r|%|62e90394-69f5-4237-9190-012177145e10|%') END AS n"
        # distinct guests (#EXT# in the UPN -- counted IN SQL, no UPN leaves) / service principals holding any active assignment
        privilegedGuests     = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(DISTINCT LOWER(PrincipalId)) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND PrincipalUpn LIKE N'%#EXT#%' AND ISNULL(PrincipalId, N'') <> N'') END AS n"
        privilegedSpns       = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(DISTINCT LOWER(PrincipalId)) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND PrincipalKind = N'servicePrincipal' AND ISNULL(PrincipalId, N'') <> N'') END AS n"
        # rows not managed by PIM (Managed = 0) -- only once the snapshot's marks were computed (MarksKey set), else unknown
        roleAssignmentsOutsidePim = "SELECT CASE WHEN $snap IS NULL OR (SELECT MarksKey FROM pim.ActiveAssignmentSnapshots WHERE SnapshotId = $snap) IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND Managed = 0) END AS n"
        assignmentsExpiring7d = "SELECT CASE WHEN $snap IS NULL THEN NULL ELSE (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows WHERE SnapshotId = $snap AND EndUtc >= SYSUTCDATETIME() AND EndUtc < DATEADD(day, 7, SYSUTCDATETIME())) END AS n"
        # the drift document's own total (pim.TenantCache kind 'drift'); no document = left out
        driftItems           = "SELECT CASE WHEN ISJSON(ValueJson) = 1 THEN TRY_CAST(JSON_VALUE(ValueJson, '$.total') AS bigint) END AS n FROM pim.TenantCache WHERE Kind = N'drift'"
        # items verify-convergence holds as not yet converged (pim.Settings 'ConvergenceState' firstSeen map); never ran = left out
        unconvergedItems     = "$(Get-PimUplinkSettingJsonSql -Name 'ConvergenceState') SELECT CASE WHEN @has = 0 OR @v IS NULL OR ISJSON(@v) = 0 THEN NULL ELSE (SELECT COUNT_BIG(*) FROM OPENJSON(@v, '$.firstSeen')) END AS n"
    }
    if ($MspMaster) { $q['managedTenants'] = 'SELECT COUNT_BIG(*) AS n FROM platform.Tenants WHERE Enabled = 1' }
    if ($HybridAd) {
        # the AD groups the worker keeps in sync: its sync memory (pim.Settings 'HybridAdSyncMemory.<job>.<bucket>', '$.g' = one
        # entry per AD group). No memory record at all = the worker never ran = left out.
        $q['hybridAdGroups'] = "SELECT CASE WHEN COUNT(*) = 0 THEN NULL ELSE COUNT_BIG(DISTINCT j.[key]) END AS n FROM pim.Settings s OUTER APPLY OPENJSON(CASE WHEN ISJSON(s.ValueJson) = 1 THEN s.ValueJson END, '$.g') j WHERE s.Name LIKE N'HybridAdSyncMemory.%'"
        # the servers the worker lists (pim.TenantCache 'ad-servers' items); no list = left out
        $q['hybridServers']  = "SELECT (SELECT COUNT_BIG(*) FROM OPENJSON(CASE WHEN ISJSON(t.ValueJson) = 1 THEN t.ValueJson END, '$.items')) AS n FROM pim.TenantCache t WHERE t.Kind = N'ad-servers' AND ISJSON(t.ValueJson) = 1"
    }
    return $q
}

function Get-PimUplinkAdoptionCounts {
    <#
      PIM 100.128. Runs each adoption query on its own (one unreadable source never hides the others) and returns
      @{ key = [long] } with ONLY the readable keys ($null when none was). -Query { param($Name, $Sql) } returns the scalar
      (the job binds Invoke-PimSqlScalar on the store's MI connection; tests pass a stub over seeded data). A throw, NULL /
      DBNull, a non-number or a negative = that key LEFT OUT. Never throws.
      -Runs (§33.0 MORE TELEMETRY): the job run history the caller READ (Get-PimJobRunHistory) -> convergenceFailures24h
      (Get-PimUplinkConvergenceFailures). $null = the history could not be read = that key left out.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [switch]$MspMaster, [switch]$HybridAd, [AllowNull()][object[]]$Runs = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = @{}
    if ($null -ne $Runs) { try { $out['convergenceFailures24h'] = [long](Get-PimUplinkConvergenceFailures -Runs $Runs -NowUtc $NowUtc) } catch { } }
    try {
        $qs = Get-PimUplinkAdoptionQueries -MspMaster:$MspMaster -HybridAd:$HybridAd
        foreach ($k in @($qs.Keys)) {
            $v = $null
            try { $v = & $Query "$k" "$($qs[$k])" } catch { continue }
            $v = @($v) | Select-Object -First 1
            if ($null -ne $v -and -not ($v -is [System.DBNull]) -and -not ($v -is [string]) -and -not ($v -is [ValueType])) { $v = Get-PimUplinkField $v 'n' }
            if ($null -eq $v -or $v -is [System.DBNull]) { continue }
            $n = 0L
            if (-not [long]::TryParse("$v", [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -or $n -lt 0) { continue }
            $out["$k"] = $n
        }
    } catch { }
    if ($out.Count -eq 0) { return $null }
    return $out
}

function Get-PimUplinkField {
    # A property of a PSCustomObject / DataRow-like object or a dictionary, $null when absent (PIM-Uplink.ps1 stands alone).
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

# PIM 100.56 / framework §8.9 ENDPOINTS (owner 2026-10-10, via Invardia: "it would be great that the url for the customers env
# is included in the email so i dont have to find it"): the IDENTIFIED heartbeat carries Endpoints [ { kind; url; label? } ].
# Invardia (packages/core endpoints.ts) refuses the WHOLE report on one bad entry -- so PIM checks every entry to the same rules
# first and leaves a bad one out: kind from the closed list and at most once, https, a DNS host, no user / password, no query
# string or fragment (secrets travel there), no white space / quotes, at most 400 characters, at most 12 entries; label at most
# 60 characters without control characters or < >. PIM adds: never an '.internal.' host (an internal Container Apps environment
# is unreachable from Invardia), never localhost / an IP / a single-label or .local name.
$script:PimUplinkEndpointKinds = @('manager', 'portal', 'api', 'activator', 'mcp', 'webapp')
$script:PimUplinkMaxEndpoints = 12

function ConvertTo-PimUplinkEndpointUrl {
    <# PURE. The url as sent (trailing '/' removed), or '' when Invardia would refuse it or it is not reachable from outside. #>
    param([AllowNull()][object]$Url)
    if ($Url -isnot [string]) { return '' }
    $s = $Url.Trim().TrimEnd('/')
    if (-not $s -or $s.Length -gt 400 -or $s -notmatch '^(?i)https://') { return '' }
    foreach ($ch in $s.ToCharArray()) { if ([int]$ch -le 32 -or [int]$ch -gt 126 -or '"''<>\`{}|^?#'.IndexOf($ch) -ge 0) { return '' } }
    $u = $null
    if (-not [Uri]::TryCreate($s, [UriKind]::Absolute, [ref]$u)) { return '' }
    if ($u.Scheme -ne 'https' -or -not $u.Host -or "$($u.UserInfo)" -or "$($u.Query)" -or "$($u.Fragment)") { return '' }
    $h = $u.Host.ToLowerInvariant()
    if ($u.HostNameType -ne [UriHostNameType]::Dns -or $h -notmatch '\.' -or $h -match '(^|\.)internal(\.|$)' -or $h -match '(^|\.)localhost$' -or $h -match '\.local$') { return '' }
    return $s
}

function Select-PimUplinkEndpoints {
    <#
      PURE. The Endpoints list as sent: each entry { kind; url; label? } (a dictionary or an object) checked; a bad entry is LEFT
      OUT (never sent -- one bad entry refuses Invardia's whole report); a kind already listed is left out (first wins); at most
      -Max (12). Returns an array of [pscustomobject] (empty when nothing is valid). Never throws.
    #>
    param([AllowNull()][object[]]$Endpoints = @(), [int]$Max = $script:PimUplinkMaxEndpoints)
    $out = New-Object System.Collections.Generic.List[object]
    if ($Max -le 0 -or $Max -gt 12) { $Max = 12 }
    foreach ($e in @($Endpoints)) {
        if ($null -eq $e -or $out.Count -ge $Max) { continue }
        try {
            $k = "$(Get-PimUplinkField $e 'kind')".Trim().ToLowerInvariant()
            if ($k -notin @('manager', 'portal', 'api', 'activator', 'mcp', 'webapp')) { continue }   # literal: child-scope safe
            if (@($out | Where-Object { $_.kind -eq $k }).Count) { continue }
            $url = ConvertTo-PimUplinkEndpointUrl (Get-PimUplinkField $e 'url')
            if (-not $url) { continue }
            $o = [ordered]@{ kind = $k; url = $url }
            $lab = Get-PimUplinkField $e 'label'
            if ($lab -is [string] -and $lab.Trim() -and $lab.Trim().Length -le 60 -and $lab -notmatch '[\x00-\x1f<>]') { $o['label'] = $lab.Trim() }
            $out.Add([pscustomobject]$o)
        } catch { continue }
    }
    # Unrolled on purpose: every caller wraps the call in @(); 'return , $arr' would nest the list inside one element.
    return $out.ToArray()
}

function New-PimUplinkEndpoints {
    <#
      PURE. What PIM has, as the §8.9 list: the hosted Manager (kind manager), the RFA portal (kind portal, label 'RFA portal')
      when the broker is deployed, the access request API on that broker (kind api, <portal>/api/v1) when 'api.broker' is on,
      the MCP server on the Manager (kind mcp, <manager>/mcp) when 'mcp.server' is on. The Activator backend is an app
      registration -- no url; PIM has no web app. A missing / unusable url leaves that entry (and what hangs off it) out.
    #>
    param([string]$ManagerUrl = '', [string]$RfaPortalUrl = '', [bool]$ApiEnabled = $false, [bool]$McpEnabled = $false)
    $m = ConvertTo-PimUplinkEndpointUrl "$ManagerUrl".Trim().Trim('"')
    $p = ConvertTo-PimUplinkEndpointUrl "$RfaPortalUrl".Trim().Trim('"')
    $c = New-Object System.Collections.Generic.List[object]
    if ($m) { $c.Add(@{ kind = 'manager'; url = $m; label = 'PIM Manager' }) }
    if ($p) { $c.Add(@{ kind = 'portal'; url = $p; label = 'RFA portal' }) }
    if ($p -and $ApiEnabled) { $c.Add(@{ kind = 'api'; url = "$p/api/v1"; label = 'Access request API' }) }
    if ($m -and $McpEnabled) { $c.Add(@{ kind = 'mcp'; url = "$m/mcp"; label = 'MCP server' }) }
    return @(Select-PimUplinkEndpoints -Endpoints $c.ToArray())
}

function Get-PimUplinkEndpoints {
    <#
      PIM 100.56. The environment's endpoints from what it ALREADY records -- no ARM read in the tick:
        manager  pim.Settings 'ManagerUrl' (the hosted Manager writes its own public address there on its first signed-in
                 request: the custom hostname when one is set, else the ingress FQDN -- R25-14 / §80.1), else the mail-link
                 resolver Get-PimPortalBaseUrl, else env PIM_MANAGER_URL;
        portal   pim.Settings 'RfaSettings'.portalUrl (written by Deploy-PimRfaBroker / Settings > RFA broker & API);
        api/mcp  the features 'api.broker' / 'mcp.server' (-FeatureOn { param($Key) } -> bool; default Test-PimFeatureAvailable).
      Never throws: anything unreadable is left out.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [scriptblock]$FeatureOn = $null)
    $mgr = ''; $portal = ''; $api = $false; $mcp = $false
    try { $v = & $GetSetting 'ManagerUrl'; if ($v -is [string]) { $mgr = $v.Trim().Trim('"') } } catch { }
    if (-not $mgr -and (Get-Command Get-PimPortalBaseUrl -ErrorAction SilentlyContinue)) { try { $mgr = "$(Get-PimPortalBaseUrl)" } catch { } }
    if (-not $mgr -and "$env:PIM_MANAGER_URL".Trim()) { $mgr = "$env:PIM_MANAGER_URL".Trim() }
    try {
        $rs = & $GetSetting 'RfaSettings'
        if ($rs -is [string] -and $rs.Trim().StartsWith('{')) { $rs = $rs | ConvertFrom-Json }
        $pu = Get-PimUplinkField $rs 'portalUrl'; if ($pu -is [string]) { $portal = $pu.Trim() }
    } catch { }
    if (-not $FeatureOn) { $FeatureOn = { param($k) [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key $k -Quiet)) } }
    try { $api = [bool](& $FeatureOn 'api.broker') } catch { $api = $false }
    try { $mcp = [bool](& $FeatureOn 'mcp.server') } catch { $mcp = $false }
    return @(New-PimUplinkEndpoints -ManagerUrl $mgr -RfaPortalUrl $portal -ApiEnabled $api -McpEnabled $mcp)
}

# PIM 100.102 GUARD TELEMETRY: CLEARED + ACTIVE NOW (owner 2026-10-12, looking at Invardia's health view of a customer hours
# after the guard was cleared: "status in invardia is not updated correctly ... i cannot trust the data ... it must be
# telemetry based"). PIM only ever said that a guard TRIPPED. Invardia's contract (same endpoint, Schema 2, both optional):
#   1. the IDENTIFIED heartbeat carries ActiveGuards [ { id; outcome; severity; sinceUtc? } ] -- what is held RIGHT NOW. The
#      list IS the state at Invardia ([] = nothing is held; the field left out = nothing changes). A malformed list (an
#      unknown outcome / severity, a duplicate id, more than 50 items) makes Invardia refuse the WHOLE heartbeat with 422, so
#      New-PimUplinkActiveGuards makes that impossible: unique ids, values from the closed lists only, at most 50.
#   2. a guard that was reported and is no longer held gets ONE Kind 'guard' record with GuardOutcome 'cleared'
#      (New-PimUplinkGuardClearedRecord), ClearedUtc = now and ClearedBy only where the stored state proves it.
# READ-ONLY: nothing here changes what a guard does, or when a hold is recorded or cleared.
# The state is the install's own: pim.Settings 'GuardHolds' { holds: [...] } (PIM-GuardRelease.ps1) and the policy change sets
# held for approval, pim.Settings '<prefix>MassHold' (PIM-EngineProviders.ps1). The setting names are literals here (this file
# stands alone; Test-PimUplink pins them to the engine's own specs).
$script:PimUplinkMaxActiveGuards = 50

function Get-PimUplinkGuardId {
    <# PURE. A guard id as sent: lower-case, ^[a-z0-9][a-z0-9.-]{0,99}$ -- or '' (never sent). #>
    param([AllowNull()][object]$Value)
    $id = "$Value".Trim().ToLowerInvariant()
    if ($id -cnotmatch '^[a-z0-9][a-z0-9.-]{0,99}$') { return '' }
    return $id
}

function ConvertTo-PimUplinkUtc {
    <# PURE. A stored time (ISO text, or the DateTime PowerShell 7's ConvertFrom-Json makes of it) as a UTC [datetime], or $null. #>
    param([AllowNull()][object]$Value)
    try {
        if ($null -eq $Value) { return $null }
        if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
        if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
        $s = "$Value".Trim(); if (-not $s) { return $null }
        return [datetimeoffset]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    } catch { return $null }
}

function ConvertTo-PimUplinkGuardOutcome {
    <#
      PURE. Invardia's closed list: halted | refused | held | skipped | warning. A value from the list is kept; anything else
      is mapped to the nearest one (a word that starts like one of them), else -Default (a hold = 'held'). Never sent raw.
    #>
    param([AllowNull()][object]$Value, [string]$Default = 'held')
    $v = "$Value".Trim().ToLowerInvariant()
    if ($v -in @('halted', 'refused', 'held', 'skipped', 'warning')) { return $v }
    if ($v -match '^(halt|stop|abort|block)') { return 'halted' }
    if ($v -match '^(refus|den|reject)') { return 'refused' }
    if ($v -match '^(hold|pend|wait)') { return 'held' }
    if ($v -match '^skip') { return 'skipped' }
    if ($v -match '^warn') { return 'warning' }
    $d = "$Default".Trim().ToLowerInvariant()
    if ($d -in @('halted', 'refused', 'held', 'skipped', 'warning')) { return $d }
    return 'held'
}

function ConvertTo-PimUplinkGuardSeverity {
    <#
      PURE. Invardia's closed list: critical | warning. A value from the list is kept; a word that means one of them is
      mapped; anything else follows the outcome exactly like a trip record does (halted / refused = critical, else warning).
    #>
    param([AllowNull()][object]$Value, [string]$Outcome = 'held')
    $v = "$Value".Trim().ToLowerInvariant()
    if ($v -in @('critical', 'warning')) { return $v }
    if ($v -match '^(crit|fatal|error|high)') { return 'critical' }
    if ($v -match '^(warn|info|low|medium|notice)') { return 'warning' }
    if ("$Outcome".Trim().ToLowerInvariant() -in @('halted', 'refused')) { return 'critical' }
    return 'warning'
}

function ConvertTo-PimUplinkGuardTripMap {
    <# PURE. pim.Settings 'GuardTrips' (an object, a dictionary or JSON text) as a hashtable guard id -> its trip entry. #>
    param([AllowNull()][object]$Trips)
    $m = @{}
    if ($null -eq $Trips) { return $m }
    $src = $Trips
    if ($src -is [string]) { try { $src = $src | ConvertFrom-Json } catch { return $m } }
    if ($null -eq $src) { return $m }
    $items = if ($src -is [System.Collections.IDictionary]) { @($src.Values) } else { @($src.PSObject.Properties | ForEach-Object { $_.Value }) }
    foreach ($e in $items) {
        if ($null -eq $e) { continue }
        $id = Get-PimUplinkGuardId (Get-PimUplinkField $e 'guardId')
        if ($id) { $m[$id] = $e }
    }
    return $m
}

function New-PimUplinkActiveGuards {
    <#
      PURE. PIM 100.102. The heartbeat's ActiveGuards from the install's own state:
        -Holds      the entries of pim.Settings 'GuardHolds' (guardId, scope, firstSeenUtc, ...). ONE item per GUARD ID: a guard
                    holding in several scopes is one item, its sinceUtc the EARLIEST first-seen of its holds.
        -MassHolds  the policy change sets held for approval: @{ provider; heldUtc } per '<prefix>MassHold' record that is set.
                    id = 'engine.policy-mass-change.<provider>' -- the catalog's guard id (Get-PimGuardReleaseCatalog) plus the
                    provider, which is exactly the GuardId of that hold's trip record, so Invardia sees ONE guard, not two.
        -Trips      pim.Settings 'GuardTrips': the guard's own trip gives outcome + severity; without one a hold is
                    'held' / 'warning'. Every value goes through the closed lists (ConvertTo-PimUplinkGuardOutcome / -Severity).
      An id that does not fit ^[a-z0-9][a-z0-9.-]{0,99}$ and the ids that are no longer guards (PIM 100.72) are left out.
      Unique by id, at most -Max (50): if ever more, the 50 with the earliest sinceUtc and ONE warning.
      Returns an array of [pscustomobject] { id; outcome; severity; sinceUtc? } (empty = nothing is held). An internal error
      THROWS (after one warning): the cycle then treats the state as unknown and sends NO ActiveGuards -- never a wrong list.
    #>
    param([AllowNull()][object[]]$Holds = @(), [AllowNull()][object[]]$MassHolds = @(), [AllowNull()][object]$Trips = $null, [int]$Max = 50)
    $out = New-Object System.Collections.Generic.List[object]
    if ($Max -le 0 -or $Max -gt 50) { $Max = 50 }   # literal ceiling: Invardia refuses the whole heartbeat above 50
    try {
        $notGuards = @('manager.commit.delta-guard', 'manager.commit.uplink-readonly', 'manager.commit.replication-gate', 'engine.ledger-unreadable', 'msp.licence')
        $tripBy = ConvertTo-PimUplinkGuardTripMap $Trips
        $by = @{}   # id -> ticks of the earliest first-seen (-1 = unknown)
        $add = {
            param($id, $when)
            if (-not $id -or $id -in $notGuards) { return }
            $t = [long]-1; if ($null -ne $when) { $t = [long]$when.Ticks }
            if (-not $by.ContainsKey($id)) { $by[$id] = $t; return }
            $cur = [long]$by[$id]
            if ($t -ge 0 -and ($cur -lt 0 -or $t -lt $cur)) { $by[$id] = $t }
        }
        foreach ($h in @($Holds)) {
            if ($null -eq $h) { continue }
            & $add (Get-PimUplinkGuardId (Get-PimUplinkField $h 'guardId')) (ConvertTo-PimUplinkUtc (Get-PimUplinkField $h 'firstSeenUtc'))
        }
        foreach ($m in @($MassHolds)) {
            if ($null -eq $m) { continue }
            $prov = ("$(Get-PimUplinkField $m 'provider')".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '')
            if (-not $prov) { continue }
            & $add (Get-PimUplinkGuardId "engine.policy-mass-change.$prov") (ConvertTo-PimUplinkUtc (Get-PimUplinkField $m 'heldUtc'))
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($id in @($by.Keys)) {
            $t = [long]$by[$id]
            $rows.Add([pscustomobject]@{ id = "$id"; ticks = $t; sort = $(if ($t -ge 0) { $t } else { [long]::MaxValue }) })
        }
        $sorted = @($rows.ToArray() | Sort-Object @{ Expression = { $_.sort } }, @{ Expression = { $_.id } })
        if ($sorted.Count -gt $Max) {
            Write-Warning ("[uplink] {0} guards hold right now -- the heartbeat lists the {1} held longest (Invardia accepts at most {1})." -f $sorted.Count, $Max)
        }
        $seen = @{}
        foreach ($r in $sorted) {
            if ($out.Count -ge $Max) { break }
            if ($seen.ContainsKey($r.id)) { continue }
            $seen[$r.id] = $true
            $trip = $null; if ($tripBy.ContainsKey($r.id)) { $trip = $tripBy[$r.id] }
            $oc = ConvertTo-PimUplinkGuardOutcome -Value (Get-PimUplinkField $trip 'outcome') -Default 'held'
            $sv = ConvertTo-PimUplinkGuardSeverity -Value (Get-PimUplinkField $trip 'severity') -Outcome $oc
            $o = [ordered]@{ id = $r.id; outcome = $oc; severity = $sv }
            if ($r.ticks -ge 0) { $o['sinceUtc'] = ([datetime]::new([long]$r.ticks, [DateTimeKind]::Utc)).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
            $out.Add([pscustomobject]$o)
        }
    } catch { Write-Warning "[uplink] the active guards could not be listed: $($_.Exception.Message)"; throw }
    # Unrolled on purpose (like Select-PimUplinkEndpoints): every caller wraps the call in @().
    return $out.ToArray()
}

function Read-PimUplinkSettingObject {
    <#
      PURE. A pim.Settings value as an object: @{ ok; value }. A value comes back parsed, as JSON text, or as JSON text
      inside a JSON string (a record written with Set-PimSetting -Value <json text>); '' / $null = nothing stored (ok, $null).
      ok = $false when it is text that does not parse -- the caller then does NOT know the state.
    #>
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2; $i++) {
        if ($v -isnot [string]) { break }
        $s = $v.Trim()
        if (-not $s) { return @{ ok = $true; value = $null } }
        try { $v = $s | ConvertFrom-Json -ErrorAction Stop } catch { return @{ ok = $false; value = $null } }
    }
    if ($v -is [string]) { if (-not $v.Trim()) { return @{ ok = $true; value = $null } }; return @{ ok = $false; value = $null } }
    return @{ ok = $true; value = $v }
}

function Get-PimUplinkGuardState {
    <#
      PIM 100.102. What the guards hold right now, read through -GetSetting { param($Name) } (pim.Settings). READ-ONLY.
      Returns @{ known; holds; massHolds; trips; releases; error }:
        known      $false when 'GuardHolds', a '<prefix>MassHold' record or 'GuardTrips' could not be read (the store threw) or
                   a hold record is text that does not parse. The heartbeat then carries NO ActiveGuards and no guard is
                   reported cleared: "I do not know" must never be sent as "nothing is held".
        holds      the 'GuardHolds' entries      massHolds  @{ provider; heldUtc } per policy hold record that is set
        trips      'GuardTrips' as stored        releases   the 'GuardReleases' entries, or $null when they could not be read
      Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting)
    $st = @{ known = $false; holds = @(); massHolds = @(); trips = $null; releases = $null; error = '' }
    try {
        $h = Read-PimUplinkSettingObject (& $GetSetting 'GuardHolds')
        if (-not $h.ok) { $st.error = "pim.Settings 'GuardHolds' is not readable"; return $st }
        $holds = New-Object System.Collections.Generic.List[object]
        foreach ($x in @(Get-PimUplinkField $h.value 'holds')) { if ($null -ne $x) { $holds.Add($x) } }
        $mass = New-Object System.Collections.Generic.List[object]
        # LITERALS (child-scope safe): the three policy breaker providers and their hold record (PIM-EngineProviders.ps1).
        $records = [ordered]@{ 'groupspolicies' = 'GroupsPolicyMassHold'; 'entrarolepolicies' = 'EntraRolePolicyMassHold'; 'azrespolicies' = 'AzResPolicyMassHold' }
        foreach ($prov in @($records.Keys)) {
            $m = Read-PimUplinkSettingObject (& $GetSetting $records[$prov])
            if (-not $m.ok) { $st.error = "pim.Settings '$($records[$prov])' is not readable"; return $st }
            if ($null -ne $m.value -and "$(Get-PimUplinkField $m.value 'planHash')".Trim()) {
                $mass.Add([pscustomobject]@{ provider = "$prov"; heldUtc = (Get-PimUplinkField $m.value 'heldUtc') })
            }
        }
        $st.trips = & $GetSetting 'GuardTrips'
        $st.holds = $holds.ToArray(); $st.massHolds = $mass.ToArray(); $st.known = $true
    } catch { $st.known = $false; $st.error = "the guard state could not be read: $($_.Exception.Message)"; return $st }
    try {
        $r = Read-PimUplinkSettingObject (& $GetSetting 'GuardReleases')
        if ($r.ok) {
            $rl = New-Object System.Collections.Generic.List[object]
            foreach ($x in @(Get-PimUplinkField $r.value 'releases')) { if ($null -ne $x) { $rl.Add($x) } }
            $st.releases = $rl.ToArray()
        }
    } catch { $st.releases = $null }
    return $st
}

function ConvertTo-PimUplinkGuardReported {
    <#
      PURE. UplinkState.guardsReported (an object or a dictionary: guard id -> { sinceUtc; hold }) as a hashtable
      id -> @{ sinceUtc (ISO text or ''); hold (bool) }. The set of guards last reported to Invardia as tripped / active.
    #>
    param([AllowNull()][object]$Value)
    $m = @{}
    if ($null -eq $Value) { return $m }
    $names = if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $id = Get-PimUplinkGuardId $n
        if (-not $id) { continue }
        $v = Get-PimUplinkField $Value "$n"
        $u = ConvertTo-PimUplinkUtc (Get-PimUplinkField $v 'sinceUtc')
        $hold = $false; try { $hold = [bool](Get-PimUplinkField $v 'hold') } catch { $hold = $false }
        $m[$id] = @{ sinceUtc = $(if ($u) { $u.ToString('o') } else { '' }); hold = $hold }
    }
    return $m
}

function Get-PimUplinkGuardClearedBy {
    <#
      PURE. PIM 100.102. How a reported guard got clear -- ONLY what the stored state proves; '' = not provable (the record
      then carries no ClearedBy, which Invardia allows):
        'released'  a guard release of THIS guard was CONSUMED (pim.Settings 'GuardReleases', status consumed) at or after
                    -SinceUtc (the guard's last trip, else when it was first reported).
        'passed'    -WasHold (this install saw the guard in 'GuardHolds') and no release of it was used: the engine removes a
                    hold in exactly two ways -- a release, or the same guard running on a writing run and allowing it.
        ''          the releases could not be read; an "until" release of the guard was used (it has no consumed time);
                    a consumed release that cannot be placed in time; the trip is older than 6 days (ended releases are kept
                    7 days, so "no release" is no longer provable); a guard that never had a 'GuardHolds' entry (a policy
                    change set held for approval, a refusal at one moment).
      'undone' is NEVER sent: a plan that was withdrawn and a plan that shrank inside the limit leave the same state.
    #>
    param([string]$GuardId = '', [bool]$WasHold = $false, [AllowNull()][object[]]$Releases = $null, [bool]$ReleasesKnown = $false,
          [AllowNull()][object]$SinceUtc = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $id = Get-PimUplinkGuardId $GuardId
        if (-not $id -or -not $ReleasesKnown) { return '' }
        $since = ConvertTo-PimUplinkUtc $SinceUtc
        $mine = @(@($Releases) | Where-Object { $null -ne $_ -and (Get-PimUplinkGuardId (Get-PimUplinkField $_ 'guardId')) -eq $id })
        $ambiguous = $false
        foreach ($r in $mine) {
            $status = "$(Get-PimUplinkField $r 'status')".Trim().ToLowerInvariant()
            if ($status -eq 'consumed') {
                $c = ConvertTo-PimUplinkUtc (Get-PimUplinkField $r 'consumedUtc')
                if ($null -ne $since -and $null -ne $c -and $c -ge $since) { return 'released' }
                if ($null -eq $since -or $null -eq $c) { $ambiguous = $true }
                continue
            }
            $used = 0; [void][int]::TryParse("$(Get-PimUplinkField $r 'usedCount')", [ref]$used)
            if ($used -gt 0) { $ambiguous = $true }
        }
        if ($ambiguous -or -not $WasHold) { return '' }
        if ($null -eq $since -or ($NowUtc.ToUniversalTime() - $since).TotalDays -gt 6) { return '' }
        return 'passed'
    } catch { return '' }
}

function New-PimUplinkGuardClearedRecord {
    <#
      PURE. PIM 100.102. The record that says a guard is CLEAR again: Schema 2, Kind 'guard', Product, GuardId,
      GuardOutcome 'cleared', ClearedUtc (this install's own time), ClearedBy only when it is released | undone | passed
      (anything else is left out -- Invardia would drop it), Job as on the trip record, and the identity exactly like a trip
      record (the claimed tenant when identified, else the install id). No Severity. $null for an id that cannot be sent.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [ValidateSet('anonymous', 'identified')][string]$Mode = 'anonymous',
          [string]$Product = 'pim-manager', [string]$Version = '', [AllowNull()][object]$Ring, [string]$InstallId = '', [string]$TenantId = '',
          [string]$ClearedBy = '', [string]$Job = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $gid = Get-PimUplinkGuardId $GuardId
    if (-not $gid) { return $null }
    $o = [ordered]@{ Schema = 2; Kind = 'guard'; Product = $Product }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    $o['GuardId'] = $gid; $o['GuardOutcome'] = 'cleared'
    $cb = "$ClearedBy".Trim().ToLowerInvariant()
    if ($cb -in @('released', 'undone', 'passed')) { $o['ClearedBy'] = $cb }
    $ts = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $o['ClearedUtc'] = $ts
    $j = ("$Job".Trim().ToLowerInvariant() -replace '[^a-z0-9.-]', '-') -replace '^[^a-z0-9]+', ''; if ($j.Length -gt 60) { $j = $j.Substring(0, 60) }; if ($j) { $o['Job'] = $j }
    if ($Mode -eq 'identified') { if ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() } } else { $o['InstallId'] = "$InstallId" }
    $o['LastSeenUtc'] = $ts
    return [pscustomobject]$o
}

function Send-PimUplinkRecord {
    <#
      §100.39 (framework §12.6b): the framework's Send-AitUplink, WITH the response body. Send-AitUplink throws the body away
      (`$null = Invoke-RestMethod ...`), and sync/_AitUplink.ps1 ships to every customer with no review step, so it is NOT
      changed: this wrapper calls it unchanged -- same https / credential guards, headers, timeout, never-throw -- and a
      function-local Invoke-RestMethod (PowerShell resolves commands through the caller's scopes; both files are dot-sourced,
      not modules) hands the call to the real cmdlet and keeps what it returned. Returns Send-AitUplink's
      { Status; Reason; Sent } + Body (the parsed JSON response, or $null). Never throws.
      -Transport is a test seam: { <Invoke-RestMethod's arguments> } -> the response. Default = the real cmdlet.
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][string]$Endpoint, [AllowNull()][string]$AccessCode, [scriptblock]$Transport = $null)
    $box = @{ body = $null; err = '' }
    $xport = if ($Transport) { $Transport } else { { Microsoft.PowerShell.Utility\Invoke-RestMethod @args } }
    # 2.4.551: keep the ERROR body too -- Invardia's 422 is {error:'invalid', fields:[...]} and names the refused field; it was lost.
    function Invoke-RestMethod { try { $resp = & $xport @args; $box.body = $resp; $resp } catch { try { $box.err = "$($_.ErrorDetails.Message)" } catch { }; throw } }
    $r = $null
    try { $r = Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode } catch { $r = [pscustomobject]@{ Status = 'failed'; Reason = "uplink POST failed: $($_.Exception.Message)"; Sent = $false } }
    $reason = "$($r.Reason)"
    $refFields = @()
    if ("$($r.Status)" -ne 'ok' -and "$($box.err)".Trim()) {
        $detail = "$($box.err)".Trim()
        # 2.4.644: the refused field names also as a FIELD of the answer (Fields), so a hold need not parse the text
        try { $ej = $detail | ConvertFrom-Json -ErrorAction Stop; if ($ej.fields) { $refFields = @(@($ej.fields) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }); $detail = "fields: $(@($ej.fields) -join ', ')" } } catch { }
        if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) }
        $reason = "$reason [$detail]"
    }
    $o = [ordered]@{ Status = "$($r.Status)"; Reason = $reason; Sent = [bool]$r.Sent; Body = $null }
    if ($refFields.Count) { $o['Fields'] = [string[]]$refFields }
    if ("$($r.Status)" -eq 'ok') { $o['Body'] = $box.body }
    return [pscustomobject]$o
}

function Get-PimUplinkSupersededBy {
    <#
      PURE. §100.39 / framework §12.6b: the licence id in a heartbeat response's `supersededBy`, or '' -- an object, a
      dictionary or JSON text; anything malformed (no field, not a string, not an id shape) is ''. Never throws.
    #>
    param([AllowNull()][object]$Body)
    try {
        if ($null -eq $Body) { return '' }
        if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return '' }; $Body = $Body | ConvertFrom-Json -ErrorAction Stop }
        $v = Get-PimUplinkField $Body 'supersededBy'
        if ($v -isnot [string]) { return '' }
        $v = $v.Trim()
        if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { return '' }
        return $v
    } catch { return '' }
}

function Get-PimUplinkEnvironmentId {
    <#
      PURE. PIM 100.167 (lane G, framework 8.16 "Order and links"): Invardia's id of THIS environment in an answer body
      (`environmentId`, a GUID; the uplink report answer or the install-key claim answer), lower-case, or ''. Invardia does not
      send it yet (2026-10-15: the uplink answer carries only supersededBy, the claim answer only the environment HANDLE) --
      read the moment it does, so the customer mail links the environment's own portal page. Never throws.
    #>
    param([AllowNull()][object]$Body)
    try {
        if ($null -eq $Body) { return '' }
        if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return '' }; $Body = $Body | ConvertFrom-Json -ErrorAction Stop }
        $v = Get-PimUplinkField $Body 'environmentId'
        if ($v -isnot [string]) { return '' }
        $v = $v.Trim().ToLowerInvariant()
        if ($v -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return '' }
        return $v
    } catch { return '' }
}

# ---------------------------------------------------------------------------------------------------------------------
# PIM 100.167 / framework DOCS/REQUIREMENTS.md 8.16 UPLINK-CAUSES (owner 2026-10-15: "across all solutions" / "each solution
# cause drop cause at least" / "or define errorcodes" / "but more context in free text is needed"). Behind the feature
# 'telemetry.causes' -- OFF until Invardia says its side is live; OFF = every record exactly as before (Test-PimErrorCodes D).
#   run record  Reports[] (max 20): one item per cause the run names -- Report (the job id), Code (pim-<area>-<nnnn>),
#               CauseClass, Action, FixedIn, RunMs; identified only: Detail (max 500, secret-scrubbed, INTERNAL).
#   heartbeat   Capabilities (closed keys, booleans; a key PIM cannot judge cheaply is left out) + Licences (the tenant's
#               subscribedSkus skuPartNumber ids) -- identified only, from ONE Graph read per heartbeat; a refused read
#               leaves both out (never a guess).
#   a refusal   Invardia refuses a whole record on a field it does not know: a record refused for its content goes ONCE more
#               without Reports / Capabilities / Licences, and they stay off for 24 h (UplinkState.causesRefusedUtc).
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimUplinkCapabilityKeys {
    <# PURE. framework 8.16: the CLOSED Capabilities keys (SI's list + PIM's additions). #>
    return @('defenderXdr', 'defenderVulnMgmt', 'mdi', 'intune', 'entraP2Pim', 'cmdb', 'sentinel', 'dataLake',
             'azureRbac', 'exchangeOnline', 'powerBi', 'hybridAd', 'tapPolicy')
}

function Get-PimUplinkCauseItemMax { <# PURE. framework 8.16: at most 20 Reports items, Detail at most 500 characters. #> return 20 }

function ConvertTo-PimUplinkCauseId {
    <# PURE. A value as an uplink id ^[a-z0-9-]{1,60}$ (lower case, other characters -> '-'), or '' when nothing is left. #>
    param([AllowNull()][string]$Value)
    $v = ("$Value".Trim().ToLowerInvariant() -replace '[^a-z0-9-]+', '-').Trim('-')
    if ($v.Length -gt 60) { $v = $v.Substring(0, 60).Trim('-') }
    return $v
}

function Get-PimUplinkCauseClasses {
    <#
      PURE. The catalog classes a run names, in the order of its text: every bracketed known class (failures, then the
      WAITING / NEEDS APPROVAL parts -- each item is a cause the owner wants to see), UNCLASSIFIED kept. When the text names
      none: -ErrorClass (RUN-NO-RESULT, CONVERGENCE, THROTTLED, a classified raw error), else for a failed run UNCLASSIFIED.
      A held run without a class -> its provider's hold class (the cycle's own rule), else the generic held-for-approval code.
    #>
    param([string]$Outcome = '', [string]$Kind = '', [string]$Text = '', [string]$NoteText = '', [string]$ErrorClass = '')
    $o = "$Outcome".Trim().ToLowerInvariant(); $k = "$Kind".Trim().ToLowerInvariant()
    if ($o -notin @('failed', 'warning')) { return @() }
    $known = @{}
    if (Get-Command Get-PimFailureCatalogCodes -ErrorAction SilentlyContinue) { try { foreach ($c in @(Get-PimFailureCatalogCodes)) { $known["$c"] = $true } } catch { } }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches("$Text $NoteText", '\[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)\]')) {
        $c = $m.Groups[1].Value
        if ($known.ContainsKey($c) -and -not $out.Contains($c)) { $out.Add($c) }
    }
    if ($out.Count) { return $out.ToArray() }
    $ec = "$ErrorClass".Trim().ToUpperInvariant()
    if ($ec) { return @($ec) }
    if ($o -eq 'failed') { return @('UNCLASSIFIED') }
    if ($k -eq 'held') {
        if ("$NoteText" -match 'GroupsPolicies') { return @('GROUP-POLICY-MASS-HOLD') }
        if ("$NoteText" -match 'EntraRolePolicies') { return @('ENTRA-POLICY-MASS-HOLD') }
        if ("$NoteText" -match 'AzResPolicies') { return @('AZ-POLICY-MASS-HOLD') }
        return @('GENERIC:held-for-approval')
    }
    if ($k -eq 'throttled') { return @('THROTTLED') }
    if ($k -eq 'interrupted') { return @('GENERIC:platform-timeout') }
    return @()   # a declared warning about itself (e.g. telemetry not delivered) is no engine cause
}

function New-PimUplinkCauseReports {
    <#
      PURE. framework 8.16: the Reports[] items of ONE run report (the cycle's plan entry -Plan: job, outcome, kind,
      durationMs, errorText, noteText, errorClass). Nothing for an ok run. Every item: Report, Code, CauseClass, Action,
      FixedIn (only when known), RunMs (when known). -Identified adds Detail: the run text's part that names the cause + the
      first engine message of that cause (-EngineFailures), through -Redact, at most 500 characters -- INTERNAL (owner,
      support, the solution's worker); a customer mail uses the catalogue's customerText only.
    #>
    param([Parameter(Mandatory)][object]$Plan, [string]$ErrorClass = '', [AllowNull()][object[]]$EngineFailures = @(),
          [bool]$Identified = $false, [scriptblock]$Redact = { param($t, $max) $x = "$t".Trim(); if ($x.Length -gt $max) { $x = $x.Substring(0, $max - 3) + '...' }; $x })
    $g = { param($n) if ($Plan -is [System.Collections.IDictionary]) { if ($Plan.Contains($n)) { $Plan[$n] } } elseif ($Plan.PSObject.Properties[$n]) { $Plan.$n } }
    $classes = @(Get-PimUplinkCauseClasses -Outcome "$(& $g 'outcome')" -Kind "$(& $g 'kind')" -Text "$(& $g 'errorText')" -NoteText "$(& $g 'noteText')" -ErrorClass $ErrorClass)
    if (-not $classes.Count) { return @() }
    $report = ConvertTo-PimUplinkCauseId "$(& $g 'job')"
    if (-not $report) { $report = 'pim-run' }
    $ms = $null; $dm = & $g 'durationMs'; $n0 = 0L; if ($null -ne $dm -and [long]::TryParse("$dm", [ref]$n0) -and $n0 -ge 0) { $ms = $n0 }
    $text = "$(& $g 'errorText') $(& $g 'noteText')"
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($cls in $classes) {
        if ($items.Count -ge (Get-PimUplinkCauseItemMax)) { break }
        $isGeneric = "$cls" -like 'GENERIC:*'
        $info = if ($isGeneric) { Get-PimFailureCodeInfo -Class '' -CauseClass ("$cls".Substring(8)) } else { Get-PimFailureCodeInfo -Class "$cls" }
        $it = [ordered]@{ Report = $report; Code = "$($info.code)"; CauseClass = "$($info.causeClass)"; Action = "$($info.action)" }
        if ("$($info.fixedIn)".Trim()) { $it['FixedIn'] = "$($info.fixedIn)".Trim() }
        if ($null -ne $ms) { $it['RunMs'] = $ms }
        if ($Identified) {
            $parts = New-Object System.Collections.Generic.List[string]
            if (-not $isGeneric) {
                $seg = [regex]::Match($text, '[^;:\r\n]{0,200}\[' + [regex]::Escape("$cls") + '\]')
                if ($seg.Success) { $parts.Add($seg.Value.Trim()) }
                $ef = @(@($EngineFailures) | Where-Object { $null -ne $_ -and "$($_.code)".Trim().ToUpperInvariant() -eq "$cls" -and "$($_.message)".Trim() }) | Select-Object -First 1
                if ($ef) { $parts.Add((("$($ef.message)" -split "`r?`n")[0]).Trim()) }
            }
            if (-not $parts.Count) { $first = (("$text" -split "`r?`n") | Where-Object { "$_".Trim() } | Select-Object -First 1); if ($first) { $parts.Add("$first".Trim()) } }
            $d = ''; if ($parts.Count) { $d = & $Redact ($parts -join ' | ') 500 }
            if ("$d".Trim()) { $it['Detail'] = "$d" }
        }
        $items.Add([pscustomobject]$it)
    }
    return $items.ToArray()
}

function Get-PimUplinkTenantCapabilities {
    <#
      PURE. framework 8.16 heartbeat: the tenant's subscribedSkus (-Skus: skuPartNumber, capabilityStatus, servicePlans
      [{ servicePlanName; provisioningStatus }]) -> @{ capabilities (ordered: closed key -> bool); licences (ids) }.
      Only a SKU in use (capabilityStatus Enabled / Warning) counts; a plan switched off for the tenant does not.
      Keys PIM judges from the licences: entraP2Pim, intune, defenderXdr, mdi, exchangeOnline, powerBi -- false only when
      the list WAS read and no plan grants it. -HybridAd $true adds hybridAd = true (the product's own hybrid feature is on).
      azureRbac, tapPolicy and SI's keys are never guessed: left out. -Skus $null (not read) = no licence-based key at all.
    #>
    param([AllowNull()][object[]]$Skus, [AllowNull()][object]$HybridAd = $null)
    $caps = [ordered]@{}; $lic = New-Object System.Collections.Generic.List[string]
    if ($null -ne $Skus) {
        $plans = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($Skus)) {
            if ($null -eq $s) { continue }
            $st = "$($s.capabilityStatus)".Trim()
            if ($st -and $st -notin @('Enabled', 'Warning')) { continue }
            $pn = "$($s.skuPartNumber)".Trim()
            if ($pn -match '^[A-Za-z0-9_.+-]{1,60}$' -and -not $lic.Contains($pn) -and $lic.Count -lt 50) { $lic.Add($pn) }
            foreach ($p in @($s.servicePlans)) {
                if ($null -eq $p) { continue }
                if ("$($p.provisioningStatus)".Trim() -eq 'Disabled') { continue }
                $n = "$($p.servicePlanName)".Trim().ToUpperInvariant(); if ($n -and -not $plans.Contains($n)) { $plans.Add($n) }
            }
        }
        $has = { param([string[]]$pat) foreach ($x in $plans) { foreach ($q in $pat) { if ($x -like $q) { return $true } } }; return $false }
        $caps['entraP2Pim'] = [bool](& $has @('AAD_PREMIUM_P2'))
        $caps['intune'] = [bool](& $has @('INTUNE_A*'))
        $caps['defenderXdr'] = [bool](& $has @('WINDEFATP', 'MDE_LITE', 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE', 'MTP', 'ATA'))
        $caps['mdi'] = [bool](& $has @('ATA'))
        $caps['exchangeOnline'] = [bool](& $has @('EXCHANGE_S_STANDARD*', 'EXCHANGE_S_ENTERPRISE*', 'EXCHANGE_S_DESKLESS*'))
        $caps['powerBi'] = [bool](& $has @('BI_AZURE_P*', 'POWER_BI_*'))
    }
    if ($HybridAd -eq $true) { $caps['hybridAd'] = $true }
    return [pscustomobject]@{ capabilities = $caps; licences = @($lic.ToArray()) }
}

# =====================================================================================================================
# §33.0 MORE TELEMETRY (owner 2026-10-16 via Invardia: "add relevant. i want data" / "also pim per domain"; Invardia
# accepted all 8 names + shapes the same day; ON by default since 2.4.644 -- Invardia live 1.0.500, SqlAccess.model rule widened 2026-10-16) -- the STRUCTURED heartbeat fields:
#   Security        { collectionUtc; domains: [ { domain; eligibleAssignments; activeAssignments; permanentAssignments;
#                     outsidePim; privilegedPrincipals; guestsPrivileged; spnsPrivileged; assignmentsExpiring7d;
#                     activations30d } ] }  -- the last COMPLETE active-assignments snapshot; at most 12 domains
#   Collections     [ { kind; state; lastCompleteUtc; lastAttemptUtc; expected; collected; note } ]
#   Jobs            [ { name; state; lastStartUtc; lastEndUtc; durationMs; prevDurationMs; nextRunUtc; failStreak;
#                     throttled24h } ]  -- enabled PRODUCT jobs only, at most 60
#   Convergence     { unconverged; persistent; oldestFirstSeenUtc }
#   Mail            { mode; engine: { ok; atUtc }; manager: { ok; atUtc } }
#   UpdatePending   { approvedVersion; lastBuiltVersion; hold; waitingSinceUtc }   -- from UpdateState
#   SqlAccess       { model; run1; run2; updaterInAdminGroup; checkedUtc }        -- the updater's verdict in UpdateState
#   FeaturesChanged [ '<area>.<name>:<on|off>' ]  -- at most 40, only features that differ from their catalog default
# ONE switch per field, ON by default (2.4.644): PIM_UPLINK_<FIELD> (PIM_UPLINK_SECURITY, ..._COLLECTIONS, ..._JOBS,
# ..._CONVERGENCE, ..._MAIL, ..._UPDATEPENDING, ..._SQLACCESS, ..._FEATURESCHANGED) = 0 / false / off / no switches it off.
# IDENTIFIED heartbeat only; additive (Invardia refuses its content -> the heartbeat goes once more without the field(s)
# its 422 names, held 24 h -- UplinkState.additiveRefusedUtc + additiveRefusedFields; a 422 naming no field = every
# additive field, as before). 🔒 PRIVACY: no UPN, display name, group / role NAME,
# host or address in any field -- counts, product job names, closed codes and times only. A field whose source cannot be
# read is LEFT OUT, never a guess.
# =====================================================================================================================
function Get-PimUplinkStateFieldNames {
    <# PURE. The structured fields, in the order the heartbeat adds them (a literal: child-scope safe). #>
    return @('Security', 'Collections', 'Jobs', 'Convergence', 'Mail', 'UpdatePending', 'SqlAccess', 'FeaturesChanged')
}

function Get-PimUplinkStateFieldSwitch {
    <# PURE. The environment variable that switches one structured field off: PIM_UPLINK_<FIELD, upper case>. #>
    param([Parameter(Mandatory)][string]$Field)
    return "PIM_UPLINK_$("$Field".Trim().ToUpperInvariant())"
}

function Test-PimUplinkStateFieldOn {
    <# PURE. ON by default (2.4.644, Invardia live 1.0.500): unset / empty / anything else = on; only 0 / false / off / no switches a field off. #>
    param([AllowNull()][string]$Value)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function Get-PimUplinkStateFieldSwitches {
    <# Field -> on? from the environment; -Values @{ <Field> = '<text>' } replaces the environment (tests). #>
    param([AllowNull()][hashtable]$Values = $null)
    $out = [ordered]@{}
    foreach ($f in (Get-PimUplinkStateFieldNames)) {
        $v = ''
        if ($null -ne $Values) { if ($Values.ContainsKey($f)) { $v = "$($Values[$f])" } }
        else { $v = "$([Environment]::GetEnvironmentVariable((Get-PimUplinkStateFieldSwitch -Field $f)))" }
        $out[$f] = (Test-PimUplinkStateFieldOn -Value $v)
    }
    return $out
}

function ConvertTo-PimUplinkIso {
    <# PURE. A stored time as ISO-8601 UTC text, or $null (sent as JSON null). #>
    param([AllowNull()][object]$Value)
    $t = ConvertTo-PimUplinkUtc $Value
    if ($t) { return $t.ToString('o') }
    return $null
}

function ConvertTo-PimUplinkCount {
    <# PURE. A whole number >= 0 as [long], or $null. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [bool]) { return $null }
    $n = 0L
    if ([long]::TryParse("$Value", [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -ge 0) { return $n }
    return $null
}

function ConvertFrom-PimUplinkStoredValue {
    <# PURE. A pim.Settings value as an object: a JSON text (also a double-encoded one) is parsed; $null / unparsable = $null. #>
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        $s = "$v".Trim(); if (-not $s) { return $null }
        try { $v = $s | ConvertFrom-Json } catch { return $null }
    }
    return $v
}

# ---- Security ----------------------------------------------------------------------------------------------------
function Get-PimUplinkSecurityDomains {
    <# PURE. Every domain Invardia accepts (extensible: a new one = an entry here + its kind below). A literal. #>
    return @('entraRoles', 'azureRoles', 'pimGroups', 'adminUnits', 'intune', 'defender', 'entraAppRoles', 'powerBi', 'hybridAd')
}

function Get-PimUplinkSecurityDomainMax { <# PURE. At most 12 domains per heartbeat (Invardia). #> return 12 }

function Get-PimUplinkSecurityKinds {
    <#
      PURE. The domains PIM fills TODAY: the active-assignments snapshot row Kind -> domain, and the engine scopes whose
      typed ledger keys (pim.ManagedKeys, '...|eligible') are that domain's eligible assignments (verified provider scopes:
      EntraRoles / RolesAUs / EntraRolesDirect = Entra roles, AzRes = Azure roles, AdminMembers / GroupMembers = PIM for Groups).
    #>
    return @(
        [ordered]@{ kind = 'entra-role';     domain = 'entraRoles'; scopes = @('EntraRoles', 'RolesAUs', 'EntraRolesDirect') }
        [ordered]@{ kind = 'azure-rbac';     domain = 'azureRoles'; scopes = @('AzRes') }
        [ordered]@{ kind = 'pim-for-groups'; domain = 'pimGroups';  scopes = @('AdminMembers', 'GroupMembers') }
    )
}

function Get-PimUplinkSecurityNoScheduleDomains {
    <# PURE. Domains whose snapshot rows carry NO end date (Azure Resource Graph returns none): permanent / expiring cannot be
       told apart there, so those two numbers are left out of that domain rather than counting every row as permanent. #>
    return @('azureRoles')
}

function Get-PimUplinkSecuritySql {
    <#
      PURE. ONE read-only batch over the last COMPLETE snapshot: one row per known kind (a kind with no active row still gets
      its row), the counts computed IN SQL -- no principal, UPN or name ever leaves the store. No complete snapshot = no row
      at all (the field is then left out).
    #>
    $kinds = @(Get-PimUplinkSecurityKinds)
    $vals = (@($kinds | ForEach-Object { "(N'$($_.kind)')" }) -join ', ')
    $elig = (@($kinds | ForEach-Object { "(k.Kind = N'$($_.kind)' AND m.Scope IN ($((@($_.scopes) | ForEach-Object { "N'$_'" }) -join ', ')))" }) -join ' OR ')
    return @"
SET NOCOUNT ON;
DECLARE @s BIGINT = (SELECT MAX(SnapshotId) FROM pim.ActiveAssignmentSnapshots WHERE State = N'complete');
IF @s IS NULL RETURN;
DECLARE @c DATETIME2 = (SELECT CompletedUtc FROM pim.ActiveAssignmentSnapshots WHERE SnapshotId = @s);
DECLARE @mk INT = CASE WHEN (SELECT MarksKey FROM pim.ActiveAssignmentSnapshots WHERE SnapshotId = @s) IS NULL THEN 0 ELSE 1 END;
SELECT k.Kind AS kind, @c AS collectionUtc, @mk AS marksKnown,
  (SELECT COUNT_BIG(*) FROM pim.ManagedKeys m WHERE m.[Key] LIKE N'%|eligible' AND ($elig)) AS eligibleAssignments,
  COUNT_BIG(a.Seq) AS activeAssignments,
  SUM(CASE WHEN a.Seq IS NOT NULL AND a.EndUtc IS NULL THEN 1 ELSE 0 END) AS permanentAssignments,
  SUM(CASE WHEN a.Seq IS NOT NULL AND a.Managed = 0 THEN 1 ELSE 0 END) AS outsidePim,
  COUNT(DISTINCT LOWER(NULLIF(a.PrincipalId, N''))) AS privilegedPrincipals,
  COUNT(DISTINCT CASE WHEN a.PrincipalUpn LIKE N'%#EXT#%' THEN LOWER(NULLIF(a.PrincipalId, N'')) END) AS guestsPrivileged,
  COUNT(DISTINCT CASE WHEN a.PrincipalKind = N'servicePrincipal' THEN LOWER(NULLIF(a.PrincipalId, N'')) END) AS spnsPrivileged,
  SUM(CASE WHEN a.EndUtc >= SYSUTCDATETIME() AND a.EndUtc < DATEADD(day, 7, SYSUTCDATETIME()) THEN 1 ELSE 0 END) AS assignmentsExpiring7d,
  (SELECT COUNT_BIG(*) FROM pim.ImpactActivations i WHERE i.Kind = k.Kind AND i.StartUtc >= DATEADD(day, -30, SYSUTCDATETIME())) AS activations30d
FROM (VALUES $vals) k(Kind)
LEFT JOIN pim.ActiveAssignmentRows a ON a.SnapshotId = @s AND a.Kind = k.Kind
GROUP BY k.Kind;
"@
}

function New-PimUplinkSecurityField {
    <#
      PURE. Security from the rows of Get-PimUplinkSecuritySql: { collectionUtc; domains = [ ... ] }, or $null (no complete
      snapshot = no rows). A number that is not a whole number >= 0 is left out of its domain; outsidePim only once the
      snapshot's marks were computed; permanent / expiring not for a domain without end dates.
    #>
    param([AllowNull()][object[]]$Rows)
    $rows = @(@($Rows) | Where-Object { $null -ne $_ -and -not ($_ -is [System.DBNull]) })
    if (-not $rows.Count) { return $null }
    $map = @{}; foreach ($k in @(Get-PimUplinkSecurityKinds)) { $map["$($k.kind)"] = "$($k.domain)" }
    $allowed = @(Get-PimUplinkSecurityDomains); $noSched = @(Get-PimUplinkSecurityNoScheduleDomains)
    $collected = $null; $domains = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $dom = $map["$(Get-PimUplinkField $r 'kind')"]
        if (-not $dom -or $allowed -notcontains $dom) { continue }
        if ($domains.Count -ge (Get-PimUplinkSecurityDomainMax)) { break }
        if ($null -eq $collected) { $collected = ConvertTo-PimUplinkIso (Get-PimUplinkField $r 'collectionUtc') }
        $marks = ("$(Get-PimUplinkField $r 'marksKnown')" -match '^(1|True)$')
        $d = [ordered]@{ domain = $dom }
        foreach ($f in 'eligibleAssignments', 'activeAssignments', 'permanentAssignments', 'outsidePim', 'privilegedPrincipals', 'guestsPrivileged', 'spnsPrivileged', 'assignmentsExpiring7d', 'activations30d') {
            if ($f -eq 'outsidePim' -and -not $marks) { continue }
            if ($f -in @('permanentAssignments', 'assignmentsExpiring7d') -and $noSched -contains $dom) { continue }
            $n = ConvertTo-PimUplinkCount (Get-PimUplinkField $r $f)
            if ($null -ne $n) { $d[$f] = $n }
        }
        $domains.Add([pscustomobject]$d)
    }
    if (-not $domains.Count) { return $null }
    return [pscustomobject][ordered]@{ collectionUtc = $collected; domains = [object[]]$domains.ToArray() }
}

# ---- Collections -------------------------------------------------------------------------------------------------
function Get-PimUplinkCollectionKinds {
    <# PURE. Collection kind -> the product job that collects it (a literal). #>
    return [ordered]@{
        directory = 'tenant-cache'; activeAssignments = 'active-assignments-snapshot'; drift = 'drift-snapshot'
        entraDiscovery = 'discovery-entra'; azureDiscovery = 'discovery-azure'; powerbi = 'discovery-powerbi'
        defender = 'discovery-defender'; intune = 'discovery-intune'; hybridAd = 'hybrid-ad-sync'
    }
}

function Get-PimUplinkSnapshotSql {
    <# PURE. The newest active-assignments snapshot (any state) + the newest complete one; read-only, one row or none. #>
    return @'
SET NOCOUNT ON;
DECLARE @l BIGINT = (SELECT MAX(SnapshotId) FROM pim.ActiveAssignmentSnapshots);
IF @l IS NULL RETURN;
SELECT s.State AS state, s.StartedUtc AS startedUtc, s.RowsExpected AS expected,
       (SELECT COUNT_BIG(*) FROM pim.ActiveAssignmentRows r WHERE r.SnapshotId = @l) AS collected,
       (SELECT MAX(CompletedUtc) FROM pim.ActiveAssignmentSnapshots WHERE State = N'complete') AS lastCompleteUtc
FROM pim.ActiveAssignmentSnapshots s WHERE s.SnapshotId = @l;
'@
}

function Get-PimUplinkRunsByName {
    <# PURE. Run history -> @{ name = @(runs newest first by startedUtc) }. #>
    param([AllowNull()][object[]]$Runs)
    $by = @{}
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $n = "$($r.name)".Trim(); if (-not $n) { continue }
        if (-not $by.ContainsKey($n)) { $by[$n] = New-Object System.Collections.Generic.List[object] }
        $by[$n].Add($r)
    }
    $out = @{}
    foreach ($k in @($by.Keys)) { $out[$k] = @($by[$k].ToArray() | Sort-Object @{ Expression = { $t = ConvertTo-PimUplinkUtc $_.startedUtc; if ($t) { $t } else { [datetime]::MinValue } } } -Descending) }
    return $out
}

function Get-PimUplinkCollectionNote {
    <# PURE. The closed note code of a run: throttled | permission | $null. Only the code leaves -- never the run's text. #>
    param([AllowNull()][object]$Run)
    if ($null -eq $Run) { return $null }
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    if ($st -eq 'throttled' -or "$($Run.detail)" -match '(?i)\b429\b|TooManyRequests|throttl') { return 'throttled' }
    if ((Get-PimUplinkRunOutcome -Run $Run) -eq 'failed' -and "$($Run.detail)" -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges|AuthorizationFailed|permission') { return 'permission' }
    return $null
}

function New-PimUplinkCollectionsField {
    <#
      PURE. Collections: one item per kind (Get-PimUplinkCollectionKinds) from the job run history; activeAssignments also
      from the snapshot table (-Snapshot: the row of Get-PimUplinkSnapshotSql, expected / collected). state: running (a run
      in progress) | never (no run recorded) | complete (newest run ok) | partial (newest a warning: throttled / held /
      interrupted) | failed. note: throttled | permission | no-worker (hybridAd: the hybrid worker is not seen) | $null.
      -HybridAdOn $false = no hybridAd item (nothing to collect). Times ISO UTC or null.
    #>
    param([AllowNull()][object[]]$Runs, [AllowNull()][object]$Snapshot = $null, [AllowNull()][object]$HybridWorkerState = $null,
          [bool]$HybridAdOn = $false, [bool]$SnapshotRead = $false)
    $by = Get-PimUplinkRunsByName -Runs $Runs
    $kinds = Get-PimUplinkCollectionKinds
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($kind in @($kinds.Keys)) {
        if ($kind -eq 'hybridAd' -and -not $HybridAdOn) { continue }
        $runs = @(); if ($by.ContainsKey($kinds[$kind])) { $runs = @($by[$kinds[$kind]]) }
        $latest = $runs | Select-Object -First 1
        $fin = @($runs | Where-Object { "$($_.finishedUtc)".Trim() -and "$($_.status)".Trim().ToLowerInvariant() -ne 'running' })
        $newestFin = $fin | Select-Object -First 1
        $okRun = @($fin | Where-Object { (Get-PimUplinkRunOutcome -Run $_) -eq 'ok' }) | Select-Object -First 1
        $state = 'never'
        if ($latest -and ("$($latest.status)".Trim().ToLowerInvariant() -eq 'running' -or -not "$($latest.finishedUtc)".Trim())) { $state = 'running' }
        elseif ($newestFin) {
            $o = Get-PimUplinkRunOutcome -Run $newestFin
            $state = switch ($o) { 'ok' { 'complete' } 'warning' { 'partial' } 'failed' { 'failed' } default { if ($okRun) { 'complete' } else { 'never' } } }
        }
        $note = Get-PimUplinkCollectionNote -Run $newestFin
        $item = [ordered]@{ kind = $kind; state = $state; lastCompleteUtc = $(if ($okRun) { ConvertTo-PimUplinkIso $okRun.finishedUtc } else { $null })
                            lastAttemptUtc = $(if ($latest) { ConvertTo-PimUplinkIso $latest.startedUtc } else { $null }); expected = $null; collected = $null; note = $note }
        if ($kind -eq 'activeAssignments' -and $SnapshotRead -and $null -ne $Snapshot) {
            $item.expected = ConvertTo-PimUplinkCount (Get-PimUplinkField $Snapshot 'expected')
            $item.collected = ConvertTo-PimUplinkCount (Get-PimUplinkField $Snapshot 'collected')
            $lc = ConvertTo-PimUplinkIso (Get-PimUplinkField $Snapshot 'lastCompleteUtc'); if ($lc) { $item.lastCompleteUtc = $lc }
            $la = ConvertTo-PimUplinkIso (Get-PimUplinkField $Snapshot 'startedUtc')
            if ($la -and (-not $item.lastAttemptUtc -or (ConvertTo-PimUplinkUtc $la) -gt (ConvertTo-PimUplinkUtc $item.lastAttemptUtc))) { $item.lastAttemptUtc = $la }
            if ($state -eq 'never' -and $lc) { $item.state = 'complete' }
        }
        if ($kind -eq 'hybridAd' -and $null -ne $HybridWorkerState -and "$(Get-PimUplinkField $HybridWorkerState 'state')" -eq 'not seen') { $item.note = 'no-worker' }
        $out.Add([pscustomobject]$item)
    }
    return $out.ToArray()   # callers wrap in @() (an empty list then stays a list)
}

# ---- Jobs --------------------------------------------------------------------------------------------------------
function Get-PimUplinkJobsMax { <# PURE. At most 60 items (Invardia). #> return 60 }

function Get-PimUplinkJobState {
    <# PURE. A run's closed state: ok | failed | warning | throttled | held | interrupted | skipped. #>
    param([AllowNull()][object]$Run)
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    if ($st -in @('skipped', 'unimplemented', 'outofscope', 'disabled', 'cancelled')) { return 'skipped' }
    if ($st -in @('throttled', 'interrupted', 'held', 'warning')) { return $st }
    $o = Get-PimUplinkRunOutcome -Run $Run
    if ($o -eq 'failed') { return 'failed' }
    if ($o -eq 'warning') { return 'warning' }
    return 'ok'
}

function New-PimUplinkJobsField {
    <#
      PURE. Jobs: one item per ENABLED job of -Schedule whose name is a PRODUCT job (-ProductNames: the shipped catalog,
      Get-PimDefaultJobSchedule) -- a name a customer typed never leaves. At most 60, by name. -StateJobs: the scheduler
      state's job list (nextRunUtc). failStreak = finished FAILED runs in a row, newest first; throttled24h = throttled runs
      that finished in the last 24 hours (the history keeps the newest 10 per job).
    #>
    param([AllowNull()][object[]]$Schedule, [AllowNull()][object[]]$Runs, [AllowNull()][string[]]$ProductNames,
          [AllowNull()][object[]]$StateJobs = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $prod = @{}; foreach ($n in @($ProductNames)) { if ("$n".Trim()) { $prod["$n".Trim().ToLowerInvariant()] = $true } }
    $next = @{}; foreach ($sj in @($StateJobs)) { if ($null -ne $sj -and "$($sj.name)".Trim()) { $next["$($sj.name)".Trim().ToLowerInvariant()] = $sj.nextRunUtc } }
    $by = Get-PimUplinkRunsByName -Runs $Runs
    $cut = $NowUtc.ToUniversalTime().AddHours(-24)
    $seen = @{}
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($j in @(@($Schedule) | Where-Object { $null -ne $_ } | Sort-Object { "$($_.name)" })) {
        $name = "$($j.name)".Trim(); $lk = $name.ToLowerInvariant()
        if (-not $name -or -not $prod.ContainsKey($lk) -or $seen.ContainsKey($lk)) { continue }
        if ($j.PSObject.Properties['enabled'] -and -not [bool]$j.enabled) { continue }
        if ($items.Count -ge (Get-PimUplinkJobsMax)) { break }
        $seen[$lk] = $true
        $runs = @(); if ($by.ContainsKey($name)) { $runs = @($by[$name]) }
        $latest = $runs | Select-Object -First 1
        $fin = @($runs | Where-Object { "$($_.finishedUtc)".Trim() -and "$($_.status)".Trim().ToLowerInvariant() -ne 'running' })
        $state = 'never'
        if ($latest -and ("$($latest.status)".Trim().ToLowerInvariant() -eq 'running' -or -not "$($latest.finishedUtc)".Trim())) { $state = 'running' }
        elseif ($fin.Count) { $state = Get-PimUplinkJobState -Run $fin[0] }
        $streak = 0; foreach ($f in $fin) { if ((Get-PimUplinkJobState -Run $f) -eq 'failed') { $streak++ } elseif ((Get-PimUplinkJobState -Run $f) -eq 'skipped') { continue } else { break } }
        $thr = @($fin | Where-Object { "$($_.status)".Trim().ToLowerInvariant() -eq 'throttled' -and ($t = ConvertTo-PimUplinkUtc $_.finishedUtc) -and $t -ge $cut }).Count
        $dur = { param($r) if ($null -eq $r -or -not $r.PSObject.Properties['durationMs']) { $null } else { ConvertTo-PimUplinkCount $r.durationMs } }
        $nx = $null
        if ($j.PSObject.Properties['nextRunUtc'] -and "$($j.nextRunUtc)".Trim()) { $nx = ConvertTo-PimUplinkIso $j.nextRunUtc }
        elseif ($next.ContainsKey($lk)) { $nx = ConvertTo-PimUplinkIso $next[$lk] }
        $items.Add([pscustomobject][ordered]@{
            name = $name; state = $state
            lastStartUtc = $(if ($latest) { ConvertTo-PimUplinkIso $latest.startedUtc } else { $null })
            lastEndUtc = $(if ($fin.Count) { ConvertTo-PimUplinkIso $fin[0].finishedUtc } else { $null })
            durationMs = $(if ($fin.Count) { & $dur $fin[0] } else { $null })
            prevDurationMs = $(if ($fin.Count -gt 1) { & $dur $fin[1] } else { $null })
            nextRunUtc = $nx; failStreak = [long]$streak; throttled24h = [long]$thr
        })
    }
    return $items.ToArray()   # callers wrap in @()
}

# ---- Convergence / Mail / UpdatePending / SqlAccess / FeaturesChanged -------------------------------------------
function New-PimUplinkConvergenceField {
    <#
      PURE. Convergence from pim.Settings 'ConvergenceState' (its firstSeen map: item key -> first seen unconverged):
      unconverged = the items, persistent = those unconverged for 60 minutes or more (the verify-convergence grace, a
      literal), oldestFirstSeenUtc. Only counts and a time leave -- the item keys name groups and people. No state = $null.
    #>
    param([AllowNull()][object]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = ConvertFrom-PimUplinkStoredValue $State
    if ($null -eq $st) { return $null }
    $fs = Get-PimUplinkField $st 'firstSeen'
    $vals = @()
    if ($fs -is [System.Collections.IDictionary]) { $vals = @($fs.Values) } elseif ($null -ne $fs) { $vals = @($fs.PSObject.Properties | ForEach-Object { $_.Value }) }
    $now = $NowUtc.ToUniversalTime(); $n = 0; $p = 0; $oldest = $null
    foreach ($v in $vals) {
        $n++
        $t = ConvertTo-PimUplinkUtc $v
        if (-not $t) { continue }
        if (($now - $t).TotalMinutes -ge 60) { $p++ }
        if (-not $oldest -or $t -lt $oldest) { $oldest = $t }
    }
    return [pscustomobject][ordered]@{ unconverged = [long]$n; persistent = [long]$p; oldestFirstSeenUtc = $(if ($oldest) { $oldest.ToString('o') } else { $null }) }
}

function ConvertTo-PimUplinkMailMode {
    <# PURE. The stored MailMode -> none | sharedMailbox | smtp (absent / unknown = sharedMailbox, every install's default). #>
    param([AllowNull()][object]$Value)
    switch -regex ("$Value".Trim().Trim('"')) {
        '^(?i)(none|off)$'                     { return 'none' }
        '^(?i)(smtp|smtprelay|relay)$'         { return 'smtp' }
    }
    return 'sharedMailbox'
}

function New-PimUplinkMailField {
    <#
      PURE. Mail { mode; engine; manager } from pim.Settings 'MailMode' and 'MailSendProof' (each identity's last REAL send:
      { ok; at; reason; mode; sender }). Only ok + the time leave -- never the sender address, the reason text or a host.
      An identity with no proof = null.
    #>
    param([AllowNull()][object]$MailMode, [AllowNull()][object]$Proof)
    $pr = ConvertFrom-PimUplinkStoredValue $Proof
    $one = {
        param($role)
        $x = Get-PimUplinkField $pr $role
        if ($null -eq $x) { return $null }
        $ok = Get-PimUplinkField $x 'ok'
        if ($null -eq $ok) { return $null }
        [pscustomobject][ordered]@{ ok = [bool]("$ok" -match '^(?i)(true|1)$'); atUtc = (ConvertTo-PimUplinkIso (Get-PimUplinkField $x 'at')) }
    }
    $mm = $MailMode; if ($mm -is [string] -and "$mm".Trim().StartsWith('"')) { try { $mm = $mm | ConvertFrom-Json } catch { } }
    return [pscustomobject][ordered]@{ mode = (ConvertTo-PimUplinkMailMode $mm); engine = (& $one 'engine'); manager = (& $one 'manager') }
}

function New-PimUplinkUpdatePendingField {
    <# PURE. UpdatePending from the environment's UpdateState record (what the ring approved, what was last built, the hold, waiting since). #>
    param([AllowNull()][object]$UpdateState)
    $us = ConvertFrom-PimUplinkStoredValue $UpdateState
    if ($null -eq $us) { return $null }
    $s = { param($k) $v = "$(Get-PimUplinkField $us $k)".Trim(); if ($v -and $v.Length -le 40 -and $v -match '^[0-9A-Za-z.+-]+$') { $v } else { $null } }
    $h = Get-PimUplinkField $us 'hold'
    return [pscustomobject][ordered]@{
        approvedVersion = (& $s 'approvedVersion'); lastBuiltVersion = (& $s 'lastBuiltVersion')
        hold = $(if ($null -eq $h) { $false } else { [bool]("$h" -match '^(?i)(true|1)$') })
        waitingSinceUtc = (ConvertTo-PimUplinkIso (Get-PimUplinkField $us 'waitingSinceUtc'))
    }
}

function New-PimUplinkSqlAccessField {
    <#
      PURE. SqlAccess from UpdateState.sqlAccess -- the verdict the UPDATER records after its access converge
      (New-PimSqlAccessVerdict, PIM-SqlAccess.ps1). The heartbeat only reads it, so the tick needs no right on the signed
      procedure. Not recorded yet = $null.
    #>
    param([AllowNull()][object]$UpdateState)
    $us = ConvertFrom-PimUplinkStoredValue $UpdateState
    $sa = Get-PimUplinkField $us 'sqlAccess'
    if ($null -eq $sa) { return $null }
    $m = "$(Get-PimUplinkField $sa 'model')".Trim()
    if ($m -notin @('least-privilege', 'broad')) { return $null }
    $b = { param($k) $v = Get-PimUplinkField $sa $k; if ($null -eq $v) { $null } else { [bool]("$v" -match '^(?i)(true|1)$') } }
    return [pscustomobject][ordered]@{ model = $m; run1 = (& $b 'run1'); run2 = (& $b 'run2'); updaterInAdminGroup = (& $b 'updaterInAdminGroup')
                                       checkedUtc = (ConvertTo-PimUplinkIso (Get-PimUplinkField $sa 'checkedUtc')) }
}

function Get-PimUplinkFeaturesChangedMax { <# PURE. At most 40 ids (Invardia). #> return 40 }

function New-PimUplinkFeaturesChangedField {
    <#
      PURE. FeaturesChanged: '<area>.<name>:<on|off>' for every feature whose resolved gate differs from its catalog
      default (-Gates: key -> enabled; -Catalog: the feature catalog). Closed ids only (the catalog's own keys; a key without
      a dot gets the area 'feature'), sorted, at most 40. Nothing changed = an empty list.
    #>
    param([AllowNull()][System.Collections.IDictionary]$Gates, [AllowNull()][object[]]$Catalog)
    if ($null -eq $Gates -or $null -eq $Catalog) { return $null }
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Catalog)) {
        $key = "$(Get-PimUplinkField $f 'key')".Trim().ToLowerInvariant()
        if (-not $key -or -not $Gates.Contains("$(Get-PimUplinkField $f 'key')")) { continue }
        $def = [bool](Get-PimUplinkField $f 'defaultEnabled'); $now = [bool]$Gates["$(Get-PimUplinkField $f 'key')"]
        if ($def -eq $now) { continue }
        $id = ($key -replace '[^a-z0-9.-]', '-'); if ($id -notmatch '\.') { $id = "feature.$id" }
        if ($id -notmatch '^[a-z0-9-]+\.[a-z0-9.-]+$') { continue }
        $ids.Add("${id}:$(if ($now) { 'on' } else { 'off' })")
    }
    return @($ids.ToArray() | Sort-Object | Select-Object -First (Get-PimUplinkFeaturesChangedMax))   # callers wrap in @(): nothing changed = []
}

function Get-PimUplinkStateFields {
    <#
      The structured fields that are SWITCHED ON and readable: an ordered map field -> value. -Switches: field -> on
      (Get-PimUplinkStateFieldSwitches). Every source is a seam: -GetSetting { param($Name) } (pim.Settings), -Query
      { param($Sql) } (rows; read-only), -Runs (the job run history; $null = not read), -Schedule / -ProductJobNames /
      -StateJobs (the jobs), -UpdateState, -Gates / -Catalog (the features), -HybridAdOn / -HybridWorkerState. Each field
      is built on its own: a source that throws leaves THAT field out, never the others. Never throws.
    #>
    [CmdletBinding()] param([AllowNull()][System.Collections.IDictionary]$Switches, [scriptblock]$GetSetting = $null, [scriptblock]$Query = $null,
          [AllowNull()][object[]]$Runs = $null, [AllowNull()][object[]]$Schedule = $null, [AllowNull()][string[]]$ProductJobNames = $null,
          [AllowNull()][object[]]$StateJobs = @(), [AllowNull()][object]$UpdateState = $null, [bool]$UpdateStateRead = $false,
          [AllowNull()][System.Collections.IDictionary]$Gates = $null, [AllowNull()][object[]]$Catalog = $null,
          [bool]$HybridAdOn = $false, [AllowNull()][object]$HybridWorkerState = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    # every local here starts with __sf (or is $out): a caller's seam scriptblock reads ITS variables through dynamic
    # scope, and a local named like one of them would shadow it (a test stub returned $null that way)
    $out = [ordered]@{}
    if ($null -eq $Switches) { return $out }
    $__sfOn = { param($f) $Switches.Contains($f) -and [bool]$Switches[$f] }
    if ((& $__sfOn 'Security') -and $Query) {
        try { $__sfSecRows = @(& $Query (Get-PimUplinkSecuritySql)); $__sfV = New-PimUplinkSecurityField -Rows $__sfSecRows; if ($null -ne $__sfV) { $out['Security'] = $__sfV } }
        catch { Write-Warning "[uplink] Security could not be read: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'Collections') -and $null -ne $Runs) {
        try {
            $__sfSnapRow = $null; $__sfSnapOk = $false
            if ($Query) { try { $__sfSnapRow = @(& $Query (Get-PimUplinkSnapshotSql)) | Select-Object -First 1; $__sfSnapOk = $true } catch { $__sfSnapOk = $false } }
            $out['Collections'] = [object[]]@(New-PimUplinkCollectionsField -Runs $Runs -Snapshot $__sfSnapRow -SnapshotRead $__sfSnapOk -HybridAdOn $HybridAdOn -HybridWorkerState $HybridWorkerState)
        } catch { Write-Warning "[uplink] Collections could not be built: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'Jobs') -and $null -ne $Runs -and $null -ne $Schedule -and $null -ne $ProductJobNames) {
        try { $out['Jobs'] = [object[]]@(New-PimUplinkJobsField -Schedule $Schedule -Runs $Runs -ProductNames $ProductJobNames -StateJobs $StateJobs -NowUtc $NowUtc) }
        catch { Write-Warning "[uplink] Jobs could not be built: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'Convergence') -and $GetSetting) {
        try { $__sfV = New-PimUplinkConvergenceField -State (& $GetSetting 'ConvergenceState') -NowUtc $NowUtc; if ($null -ne $__sfV) { $out['Convergence'] = $__sfV } }
        catch { Write-Warning "[uplink] Convergence could not be read: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'Mail') -and $GetSetting) {
        try { $out['Mail'] = New-PimUplinkMailField -MailMode (& $GetSetting 'MailMode') -Proof (& $GetSetting 'MailSendProof') }
        catch { Write-Warning "[uplink] Mail could not be read: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'UpdatePending') -and $UpdateStateRead) {
        try { $__sfV = New-PimUplinkUpdatePendingField -UpdateState $UpdateState; if ($null -ne $__sfV) { $out['UpdatePending'] = $__sfV } } catch { Write-Warning "[uplink] UpdatePending could not be built: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'SqlAccess') -and $UpdateStateRead) {
        try { $__sfV = New-PimUplinkSqlAccessField -UpdateState $UpdateState; if ($null -ne $__sfV) { $out['SqlAccess'] = $__sfV } } catch { Write-Warning "[uplink] SqlAccess could not be built: $($_.Exception.Message)" }
    }
    if ((& $__sfOn 'FeaturesChanged') -and $null -ne $Gates -and $null -ne $Catalog) {
        try { $out['FeaturesChanged'] = [string[]]@(New-PimUplinkFeaturesChangedField -Gates $Gates -Catalog $Catalog) } catch { Write-Warning "[uplink] FeaturesChanged could not be built: $($_.Exception.Message)" }
    }
    return $out
}

function Add-PimUplinkStateFields {
    <#
      Adds the structured fields of -Fields (Get-PimUplinkStateFields) to the heartbeat -Record, each PROVEN in the record's
      own JSON text before it leaves (the ActiveGuards lesson: Windows PowerShell 5.1 can write a list as {"value":[..]}):
      a list field must read as a JSON array, Security's domains too -- else that field is removed with one warning. Only
      the declared names are taken. Returns the names that went on the record (the caller passes them to the additive hold).
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][System.Collections.IDictionary]$Fields)
    $added = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Fields) { return [string[]]@() }
    $lists = @('Collections', 'Jobs', 'FeaturesChanged')
    foreach ($f in (Get-PimUplinkStateFieldNames)) {
        if (-not $Fields.Contains($f) -or $null -eq $Fields[$f]) { continue }
        $val = $Fields[$f]
        if ($lists -contains $f) { $val = [object[]]@($val) }
        $Record | Add-Member -NotePropertyName $f -NotePropertyValue $val -Force
        $txt = ''; try { $txt = "$($Record | ConvertTo-Json -Depth 6 -Compress)" } catch { $txt = '' }
        $ok = [bool]$txt
        if ($ok -and $lists -contains $f) { $ok = $txt.Contains("`"${f}`":[") }
        if ($ok -and $f -eq 'Security') { $ok = $txt.Contains('"domains":[') }
        if ($ok) { $added.Add($f) }
        else { $Record.PSObject.Properties.Remove($f); Write-Warning "[uplink] $f could not be written as the agreed JSON -- the heartbeat goes without it." }
    }
    return [string[]]$added.ToArray()
}

function Invoke-PimUplinkCycle {
    <#
      One cycle with every seam injected (tests run it offline):
        -GetSetting { param($Name) } / -SetSetting { param($Name, $Value) } -- pim.Settings
        -Send { param($Record, $Endpoint, $AccessCode) }                     -- returns @{ Status; Reason; Body? } (Send-PimUplinkRecord)
          §100.39: a heartbeat response carrying `supersededBy: <licenceId>` is stored in pim.Settings 'LicenceSupersededBy'
          (a plain string); the licence-request job (every 30 min) then knocks with currentLicenceId (PIM-LicenceRequest.ps1).
        -Runs <job run history>  -License <Get-PimLicense>  -ProHere <bool>
      Returns @{ ran; mode; sent; failed; heartbeat; message }.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting, [Parameter(Mandatory)][scriptblock]$Send,
          [bool]$Enabled = $false, [string]$InstallKey = '', [string]$Version = '', [AllowNull()][object]$Ring, [object[]]$Runs = @(),
          [AllowNull()][object]$License, [bool]$ProHere = $false, [string]$TenantId = '', [string]$RuntimeIdentity = 'mi-container',
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxPerCycle = $script:PimUplinkMaxRunsPerCycle, [int]$PauseMs = 0,
          # PIM 100.10 / framework 8.7 UPLINK-SETUP: the Kind=setup report (identified mode only; daily + on change).
          [bool]$SetupEnabled = $false, [AllowNull()][object]$SetupFacts = $null, [bool]$SetupExtended = $false,
          # PIM 100.36: @{ sqlUsedMb; sqlMaxMb } (Get-PimUplinkSqlSpace) -> the IDENTIFIED heartbeat's Counts; $null = left out.
          [AllowNull()][hashtable]$SqlSpace = $null,
          # framework 8.11 ASSET-COUNTS (owner 2026-10-10): @{ users; guests; servicePrincipals } the tick recorded
          # (pim.Settings 'TenantObjectCounts') -> the IDENTIFIED heartbeat's Counts; a missing / non-number key is left out.
          [AllowNull()][hashtable]$AssetCounts = $null,
          # PIM 100.128: { } -> @{ key = [long] } (Get-PimUplinkAdoptionCounts). INVOKED ONLY when the IDENTIFIED heartbeat is
          # due (once an hour), never otherwise; its keys join the heartbeat's Counts (an existing key is never overwritten).
          [AllowNull()][scriptblock]$AdoptionCounts = $null,
          # PIM 100.56 / framework 8.9 ENDPOINTS: [ { kind; url; label? } ] (Get-PimUplinkEndpoints) -> the IDENTIFIED heartbeat's
          # Endpoints, checked entry by entry (Select-PimUplinkEndpoints); the manager url is also the base of every guard's Link.
          [AllowNull()][object[]]$Endpoints = @(),
          # PIM 100.34: send FixKind unless PIM_UPLINK_FIXKIND is 0/false/off/no (ON by default -- Invardia live 6f2dce4).
          [bool]$FixKind = (Test-PimUplinkFixKindEnabled),
          # Lane repfix (2026-10-12) -- the ADDITIVE fields, ON unless PIM_UPLINK_ADDITIVE is 0/false/off/no, and held back for
          # 24 h after Invardia refused them (UplinkState.additiveRefusedUtc): Outcome ok|warning|held|failed + ActionBy on
          # every run and guard record (100.99 / 100.111), Solution (100.115), InstallRole / ManagingTenantId and Controls
          # on the identified heartbeat (100.103), the updater's own run report (job 'pim-update').
          [bool]$Additive = (Test-PimUplinkAdditiveEnabled),
          # the product's own scenario role ('single' | 'msp-master' | 'msp-managed'; anything else = InstallRole left out)
          [string]$ScenarioRole = '', [string]$ManagingTenantId = '',
          # the currently-failing items (pim.Settings 'EngineItemFailures'): their own names fill the Solution text
          [AllowNull()][object[]]$EngineFailures = @(),
          # the updater's last run as a run (ConvertTo-PimUplinkUpdateRun), or $null
          [AllowNull()][object]$UpdateRun = $null,
          # the heartbeat interval (a product constant: one hour). A parameter only so a test can keep an older timeline.
          [double]$HeartbeatHours = (Get-PimUplinkHeartbeatHours),
          # PIM 100.167 / framework 8.16 UPLINK-CAUSES: Reports[] on run records, Capabilities + Licences on the identified
          # heartbeat. OFF by default (feature 'telemetry.causes'): OFF = every record exactly as before.
          [bool]$Causes = $false,
          # { } -> the tenant's subscribedSkus (skuPartNumber, capabilityStatus, servicePlans); invoked ONLY when the identified
          # heartbeat is due and -Causes is on; a throw = Capabilities / Licences left out.
          [AllowNull()][scriptblock]$LicenceProbe = $null,
          # $true when the product's hybrid AD feature is on (Capabilities.hybridAd); anything else = left out
          [AllowNull()][object]$HybridAd = $null,
          # PIM 100.158 / framework 12.11e CR3: wave + releaseMode on the IDENTIFIED heartbeat (PIM-ReleaseControl.ps1,
          # Get-PimReleaseControlHeartbeatFields: only the keys that are known). Its own switch (PIM_Telemetry_ReleaseControl,
          # AUTO = ring 0 only) and its own 24-hour hold after a refusal (UplinkState.releaseControlRefusedUtc).
          [bool]$ReleaseControl = $false,
          [AllowNull()][System.Collections.IDictionary]$ReleaseControlFields = $null,
          # §33.0 MORE TELEMETRY: { } -> the switched-on structured fields (Get-PimUplinkStateFields: field -> value). INVOKED
          # ONLY when the IDENTIFIED heartbeat is due and the additive fields are on; $null = none.
          [AllowNull()][scriptblock]$StateFields = $null)
    $NowUtc = $NowUtc.ToUniversalTime()
    $endpoint = "$(& $GetSetting 'UplinkEndpoint')".Trim()
    $sender = Resolve-AitUplinkSender -Enabled $Enabled -InstallKey $InstallKey -Endpoint $endpoint
    if ($sender.Mode -eq 'disabled') {
        # §11 opt-out: switched OFF after it was on -> ONE 'optout' report (with the credential telemetry used), then silence.
        $st0 = & $GetSetting 'UplinkState'
        if ((Get-PimUplinkConsentAction -State $st0 -Enabled $false) -ne 'optout') { return @{ ran = $false; mode = 'disabled'; sent = 0; failed = 0; heartbeat = $false; message = "telemetry is off (feature 'telemetry.uplink')" } }
        $cred = Resolve-AitUplinkSender -Enabled $true -InstallKey $InstallKey -Endpoint $endpoint
        $rec = New-PimUplinkConsentReport -Kind optout -Mode $cred.Mode -Version $Version -Ring $Ring -InstallId "$(& $GetSetting 'TelemetryInstallId')" -TenantId $TenantId -Now $NowUtc
        $ok = $true; $why = ''
        if ($rec) { $r = & $Send $rec $cred.Endpoint $cred.AccessCode; $ok = ("$($r.Status)" -eq 'ok'); $why = "$($r.Reason)" }
        $msg = if ($ok) { "telemetry is off -- the opt-out was reported to Invardia; nothing else is sent" } else { "telemetry is off -- the opt-out report was NOT delivered ($why); it is retried next cycle, nothing else is sent" }
        $ns = [ordered]@{}; if ($st0) { foreach ($pp in $st0.PSObject.Properties) { $ns[$pp.Name] = $pp.Value } }
        if ($ok) { $ns['consent'] = 'off'; $ns['consentUtc'] = $NowUtc.ToString('o') }
        $ns['lastCycleUtc'] = $NowUtc.ToString('o'); $ns['lastResult'] = $msg; $ns['lastFailed'] = $(if ($ok) { 0 } else { 1 })
        & $SetSetting 'UplinkState' ([pscustomobject]$ns)
        return @{ ran = $true; mode = 'disabled'; sent = $(if ($ok -and $rec) { 1 } else { 0 }); failed = $(if ($ok) { 0 } else { 1 }); heartbeat = $false; consent = $(if ($ok) { 'optout' } else { '' }); message = $msg; reasons = @($(if (-not $ok) { "optout: $why" })) }
    }
    $iid = "$(& $GetSetting 'TelemetryInstallId')".Trim()
    if ($iid -notmatch '^[0-9a-fA-F-]{36}$') { $iid = [guid]::NewGuid().ToString(); & $SetSetting 'TelemetryInstallId' $iid }
    $state = & $GetSetting 'UplinkState'
    $lastHb = if ($state -and $state.PSObject.Properties['lastHeartbeatUtc']) { $state.lastHeartbeatUtc } else { $null }
    # The FLOOR: the first cycle starts it at NOW-24h, so switching telemetry on reports the last day, not the whole history.
    # It never moves after that; each job then has its own watermark (jobMarks) that moves only when ITS report landed.
    $floor = if ($state -and $state.PSObject.Properties['runWatermarkUtc'] -and "$($state.runWatermarkUtc)") { $state.runWatermarkUtc } else { $NowUtc.AddHours(-24).ToString('o') }
    $marks = @{}
    if ($state -and $state.PSObject.Properties['jobMarks'] -and $state.jobMarks) {
        if ($state.jobMarks -is [System.Collections.IDictionary]) { foreach ($k in $state.jobMarks.Keys) { $marks["$k"] = "$($state.jobMarks[$k])" } }
        else { foreach ($p in $state.jobMarks.PSObject.Properties) { $marks["$($p.Name)"] = "$($p.Value)" } }
    }
    # PIM 100.56: the checked endpoints -- IDENTIFIED only (an anonymous Community install names no host). Best-effort.
    $eps = @(); $mgrBase = ''
    if ($sender.Mode -eq 'identified') {
        try { $eps = @(Select-PimUplinkEndpoints -Endpoints @($Endpoints)) } catch { $eps = @() }
        $mgrBase = "$(@($eps | Where-Object { $_.kind -eq 'manager' } | Select-Object -First 1).url)"
    }
    # PIM 100.102: what the guards hold RIGHT NOW (read-only). $guardsKnown = $false (the store threw / a hold record does not
    # parse) = "I do not know": no ActiveGuards on the heartbeat and no guard is reported cleared this cycle.
    $gState = Get-PimUplinkGuardState -GetSetting $GetSetting
    $guardsKnown = [bool]$gState.known
    $activeNow = @(); $activeIds = @{}; $holdIds = @{}; $tripBy = @{}
    if ($guardsKnown) {
        try {
            $activeNow = @(New-PimUplinkActiveGuards -Holds $gState.holds -MassHolds $gState.massHolds -Trips $gState.trips)
            foreach ($a in $activeNow) { $activeIds["$($a.id)"] = $true }
            foreach ($h in @($gState.holds)) { $hid = Get-PimUplinkGuardId (Get-PimUplinkField $h 'guardId'); if ($hid) { $holdIds[$hid] = $true } }
            $tripBy = ConvertTo-PimUplinkGuardTripMap $gState.trips
        } catch { $guardsKnown = $false; $activeNow = @(); $activeIds = @{}; $holdIds = @{}; $tripBy = @{} }
    }
    # The guards last reported to Invardia as tripped / active: UplinkState.guardsReported { <guard id>: { sinceUtc; hold } }.
    # A state written before 100.102 has none: it starts from every guard whose trip record was sent (GuardTrips lastSentUtc),
    # so a guard that is long clear here and still open at Invardia gets its 'cleared' record on the first cycle.
    $hadReported = [bool]($state -and $state.PSObject.Properties['guardsReported'])
    $reported = @{}
    if ($hadReported) { $reported = ConvertTo-PimUplinkGuardReported $state.guardsReported }
    elseif ($guardsKnown) {
        foreach ($tid0 in @($tripBy.Keys)) {
            $ls = ConvertTo-PimUplinkUtc (Get-PimUplinkField $tripBy[$tid0] 'lastSentUtc')
            if ($ls) { $reported["$tid0"] = @{ sinceUtc = $ls.ToString('o'); hold = $false } }
        }
    }
    $common = @{ Mode = $sender.Mode; Product = $script:PimUplinkProduct; Version = $Version; Ring = $Ring; InstallId = $iid; TenantId = $TenantId; Now = $NowUtc }
    $sent = 0; $failed = 0; $why = @(); $supNote = ''; $hbSent = $false; $stopped = $false; $budget = [Math]::Max(1, $MaxPerCycle)
    $post = { param($rec) if ($sent -gt 0 -and $PauseMs -gt 0) { Start-Sleep -Milliseconds $PauseMs }; & $Send $rec $sender.Endpoint $sender.AccessCode }
    # Lane repfix: the additive fields. $postAdd sends a record that carries some (-names); when Invardia refuses its CONTENT
    # (400 / 422) the same record goes ONCE more in its old form (-legacy: the old value of a field that existed before; a
    # field that did not exist is removed) and, when that lands, the additive fields are off for the rest of this cycle and
    # for 24 hours. A refusal for any other reason (429, 5xx, no network) is returned as it is.
    $addPrev = $null; if ($state -and $state.PSObject.Properties['additiveRefusedUtc']) { $addPrev = $state.additiveRefusedUtc }
    $addHeld = Test-PimUplinkAdditiveHeld -RefusedUtc $addPrev -NowUtc $NowUtc
    # 2.4.644: a hold of NAMED additive fields only (UplinkState.additiveRefusedFields, e.g. "SqlAccess"): the other additive
    # fields keep going, only those are left out for the 24 h. No list stored = the whole group is held (as before).
    $addPrevFields = @(); if ($addHeld -and $state -and $state.PSObject.Properties['additiveRefusedFields']) { $addPrevFields = @(ConvertTo-PimUplinkHeldFieldList $state.additiveRefusedFields) }
    $addPartial = [bool]($addHeld -and $addPrevFields.Count)
    $addState = @{ on = ([bool]$Additive -and (-not $addHeld -or $addPartial)); refusedNow = $false; reason = ''; info = $null
                   held = @($addPrevFields); fields = @(); whole = $false }
    # §33.0 BUG (2026-10-16): WHAT a hold refused (New-PimUplinkRefusalInfo) + one console line. Never stops the record or the hold.
    $noteRefusal = {
        param($st, $what, $rec, $reason)
        try {
            if ($null -eq $st.info) { $st.info = New-PimUplinkRefusalInfo -Record $rec -Reason "$reason" -NowUtc $NowUtc -AccessCode "$($sender.AccessCode)" }
            Write-Warning "[uplink] $(Format-PimUplinkRefusalLine -What $what -Info $st.info) -- sent without them, held 24 h"
        } catch { try { Write-Warning "[uplink] Invardia refused the $what -- what was refused could not be recorded: $($_.Exception.Message)" } catch { } }
    }
    # 2.4.644: the additive fields under a per-field hold leave the record BEFORE its first send (their old value back, else
    # removed); returns the additive names still on the record. Every layer calls it first -- idempotent.
    $stripHeld = {
        param($rec, $names, $legacy)
        $nm = @(@($names) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
        if ($null -eq $rec -or -not @($addState.held).Count -or -not $nm.Count) { return $nm }
        $keep = @()
        foreach ($n in $nm) {
            if (@($addState.held) -contains $n) {
                if ($legacy -and $legacy.ContainsKey("$n")) { $rec | Add-Member -NotePropertyName "$n" -NotePropertyValue $legacy["$n"] -Force }
                else { $rec.PSObject.Properties.Remove("$n") }
            } else { $keep += $n }
        }
        return $keep
    }
    $addWhat = { param($f) if (@($f).Count) { "new report fields ($(@($f) -join ', '))" } else { 'new report fields' } }
    # 2.4.644: a refusal that NAMES its fields (Resolve-PimUplinkRefusalSplit) -- each hold acts only on a named field of ITS
    # group (release-control: wave / releaseMode; causes: Reports / Capabilities / Licences; additive: the named ones only),
    # the record goes ONCE more without exactly those, and that answer is returned (never a loop). $null = nothing named that
    # this record carries -> the caller does as before (the fail-safe cascade).
    $postNamed = {
        param($rec, $r1, $names, $legacy, $cnames, $rnames)
        $rf = @(); try { if ($r1 -is [System.Collections.IDictionary]) { if ($r1.Contains('Fields')) { $rf = @($r1['Fields']) } } elseif ($r1.PSObject.Properties['Fields']) { $rf = @($r1.Fields) } } catch { $rf = @() }
        $sp = $null; try { $sp = Resolve-PimUplinkRefusalSplit -Reason "$($r1.Reason)" -Fields $rf -Additive @($names) -Causes @($cnames) -Rc @($rnames) } catch { $sp = $null }
        if ($null -eq $sp -or -not $sp.act) { return $null }
        foreach ($n in @($sp.drop)) {
            if ($legacy -and $legacy.ContainsKey("$n") -and @($sp.additive) -contains "$n") { $rec | Add-Member -NotePropertyName "$n" -NotePropertyValue $legacy["$n"] -Force }
            else { $rec.PSObject.Properties.Remove("$n") }
        }
        if ($sp.rc) { $rcState.on = $false; $rcState.refusedNow = $true; $rcState.reason = "$($r1.Reason)"; & $noteRefusal $rcState 'release-control fields (wave / releaseMode)' $rec $r1.Reason }
        if ($sp.causes) { $causeState.on = $false; $causeState.refusedNow = $true; $causeState.reason = "$($r1.Reason)"; & $noteRefusal $causeState 'cause fields (Reports / Capabilities / Licences)' $rec $r1.Reason }
        if (@($sp.additive).Count) {
            $addState.refusedNow = $true; $addState.reason = "$($r1.Reason)"
            $addState.fields = @(@($addState.fields) + @($sp.additive) | Select-Object -Unique)
            $addState.held = @(@($addState.held) + @($sp.additive) | Select-Object -Unique)   # the rest of this cycle leaves them out too
            & $noteRefusal $addState (& $addWhat $sp.additive) $rec $r1.Reason
        }
        return (& $post $rec)
    }
    $postAdd = {
        param($rec, $names, $legacy)
        $nm = @(& $stripHeld $rec $names $legacy)
        $r1 = & $post $rec
        if ("$($r1.Status)" -eq 'ok' -or $null -eq $rec -or -not $nm.Count -or -not (Test-PimUplinkValidationRefusal "$($r1.Reason)")) { return $r1 }
        $rN = & $postNamed $rec $r1 $nm $legacy @() @()
        if ($null -ne $rN) { return $rN }
        foreach ($n in $nm) {
            if ($legacy -and $legacy.ContainsKey("$n")) { $rec | Add-Member -NotePropertyName "$n" -NotePropertyValue $legacy["$n"] -Force }
            else { $rec.PSObject.Properties.Remove("$n") }
        }
        $r2 = & $post $rec
        if ("$($r2.Status)" -eq 'ok') { $addState.on = $false; $addState.refusedNow = $true; $addState.whole = $true; $addState.reason = "$($r1.Reason)"; & $noteRefusal $addState 'new report fields' $rec $r1.Reason }
        return $r2
    }
    # PIM 100.167 / framework 8.16: the cause fields (Reports / Capabilities / Licences) -- their own switch and their own
    # 24-hour hold after a refusal (UplinkState.causesRefusedUtc), so a refusal of them never turns the additive fields off.
    # $postCause: the record goes as built; refused for its CONTENT while it carries cause fields (-cnames) -> a refusal that
    # names its fields is split by group ($postNamed); one that names nothing removes them, holds them 24 h, and the record
    # goes on through $postAdd (which handles the additive fields as before).
    $causePrev = $null; if ($state -and $state.PSObject.Properties['causesRefusedUtc']) { $causePrev = $state.causesRefusedUtc }
    $causeHeld = Test-PimUplinkAdditiveHeld -RefusedUtc $causePrev -NowUtc $NowUtc
    $causeState = @{ on = ([bool]$Causes -and -not $causeHeld); refusedNow = $false; reason = ''; info = $null }
    $postCause = {
        param($rec, $names, $legacy, $cnames)
        $cn = @(@($cnames) | Where-Object { "$_".Trim() })
        if (-not $cn.Count -or $null -eq $rec) { return (& $postAdd $rec $names $legacy) }
        $nm = @(& $stripHeld $rec $names $legacy)
        $r1 = & $post $rec
        if ("$($r1.Status)" -eq 'ok' -or -not (Test-PimUplinkValidationRefusal "$($r1.Reason)")) { return $r1 }
        $rN = & $postNamed $rec $r1 $nm $legacy $cn @()
        if ($null -ne $rN) { return $rN }
        foreach ($n in $cn) { $rec.PSObject.Properties.Remove("$n") }
        $causeState.on = $false; $causeState.refusedNow = $true; $causeState.reason = "$($r1.Reason)"
        & $noteRefusal $causeState 'cause fields (Reports / Capabilities / Licences)' $rec $r1.Reason
        return (& $postAdd $rec $nm $legacy)
    }
    # PIM 100.158 CR3: the release-control fields (wave / releaseMode) -- their own hold. $postRc sends a heartbeat that carries
    # them (-rnames); refused for its CONTENT -> a refusal that names its fields is split by group ($postNamed: a 422 naming
    # only SqlAccess.model never holds wave / releaseMode); one that names nothing removes them, holds them 24 h, and the
    # heartbeat goes on through $postCause (the old fail-safe cascade).
    $rcPrev = $null; if ($state -and $state.PSObject.Properties['releaseControlRefusedUtc']) { $rcPrev = $state.releaseControlRefusedUtc }
    $rcHeld = Test-PimUplinkAdditiveHeld -RefusedUtc $rcPrev -NowUtc $NowUtc
    $rcState = @{ on = ([bool]$ReleaseControl -and -not $rcHeld); refusedNow = $false; reason = ''; info = $null }
    $postRc = {
        param($rec, $names, $legacy, $cnames, $rnames)
        $rn = @(@($rnames) | Where-Object { "$_".Trim() })
        if (-not $rn.Count -or $null -eq $rec) { return (& $postCause $rec $names $legacy $cnames) }
        $nm = @(& $stripHeld $rec $names $legacy)
        $r1 = & $post $rec
        if ("$($r1.Status)" -eq 'ok' -or -not (Test-PimUplinkValidationRefusal "$($r1.Reason)")) { return $r1 }
        $rN = & $postNamed $rec $r1 $nm $legacy @(@($cnames) | Where-Object { "$_".Trim() }) $rn
        if ($null -ne $rN) { return $rN }
        foreach ($n in $rn) { $rec.PSObject.Properties.Remove("$n") }
        $rcState.on = $false; $rcState.refusedNow = $true; $rcState.reason = "$($r1.Reason)"
        & $noteRefusal $rcState 'release-control fields (wave / releaseMode)' $rec $r1.Reason
        return (& $postCause $rec $nm $legacy $cnames)
    }
    $isId = ($sender.Mode -eq 'identified')
    $redact ={ param($t, $max) $x = "$t".Trim(); if (Get-Command ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $x = ConvertTo-AitUplinkRedacted -Text $x }; if ($x.Length -gt $max) { $x = $x.Substring(0, $max - 3) + '...' }; $x }
    # §11 opt-in: switched back ON after an opt-out -> ONE 'optin' report FIRST. Until it lands nothing else is sent (Invardia
    # still has this environment as opted out), and nothing from the opted-out period is ever sent: the floor restarts NOW.
    $consent = 'on'
    if ((Get-PimUplinkConsentAction -State $state -Enabled $true) -eq 'optin') {
        $oi = New-PimUplinkConsentReport -Kind optin -Mode $sender.Mode -Version $Version -Ring $Ring -InstallId $iid -TenantId $TenantId -Now $NowUtc
        $r = & $post $oi
        if ("$($r.Status)" -eq 'ok') { $sent++; $floor = $NowUtc.ToString('o'); $marks = @{}; $lastHb = $null }
        else { $failed++; $stopped = $true; $consent = 'off'; $why += "optin: $($r.Reason)" }
    }
    if (-not $stopped -and (Get-PimUplinkHeartbeatDue -LastHeartbeatUtc $lastHb -NowUtc $NowUtc -Hours $HeartbeatHours)) {
        # PIM 100.36: the SQL space, identified heartbeat only, both numbers or neither (never a 0 / a guess).
        $hbCounts = $null
        if ($sender.Mode -eq 'identified' -and $SqlSpace -and $SqlSpace.ContainsKey('sqlUsedMb') -and $SqlSpace.ContainsKey('sqlMaxMb') -and
            $null -ne $SqlSpace['sqlUsedMb'] -and $null -ne $SqlSpace['sqlMaxMb'] -and [int64]$SqlSpace['sqlMaxMb'] -gt 0) {
            $hbCounts = @{ sqlUsedMb = [int64]$SqlSpace['sqlUsedMb']; sqlMaxMb = [int64]$SqlSpace['sqlMaxMb'] }
        }
        if ($sender.Mode -eq 'identified' -and $AssetCounts) {
            foreach ($k in 'users', 'guests', 'servicePrincipals', 'groups', 'usersTotal', 'usersDisabled') {
                $n = 0L
                if ($AssetCounts.ContainsKey($k) -and $null -ne $AssetCounts[$k] -and [long]::TryParse("$($AssetCounts[$k])", [ref]$n) -and $n -ge 0) {
                    if ($null -eq $hbCounts) { $hbCounts = @{} }
                    $hbCounts[$k] = $n
                }
            }
        }
        if ($sender.Mode -eq 'identified' -and $AdoptionCounts) {
            # PIM 100.128: computed here, once per heartbeat; a failure leaves every adoption key out, never the heartbeat.
            $ad = $null; try { $ad = & $AdoptionCounts } catch { $ad = $null }
            $ad = @($ad | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -First 1
            if ($ad) {
                foreach ($k in (Get-PimUplinkAdoptionCountKeys)) {
                    $n = 0L
                    if ($ad.Contains($k) -and $null -ne $ad[$k] -and [long]::TryParse("$($ad[$k])", [ref]$n) -and $n -ge 0) {
                        if ($null -eq $hbCounts) { $hbCounts = @{} }
                        if (-not $hbCounts.ContainsKey($k)) { $hbCounts[$k] = $n }
                    }
                }
            }
        }
        # §33.0 MORE TELEMETRY: the 40-key ceiling, enforced HERE (a record above it is refused WHOLE by Invardia) -- the
        # lowest-priority keys are dropped, deterministically, with one warning (Limit-PimUplinkCounts).
        $hbCounts = Limit-PimUplinkCounts -Counts $hbCounts
        $hb = New-AitUplinkReport -Kind heartbeat @common -Edition (Get-PimUplinkEdition -License $License -ProHere $ProHere) -Hosting 'container' `
                -RuntimeIdentity $RuntimeIdentity -LicenceState (Get-PimUplinkLicenceState -License $License) -Counts $hbCounts
        # §100.39 / framework §12.6b: the IDENTIFIED heartbeat names the installed licence (Invardia 1.0.230: optional `LicenceId`,
        # a GUID; a bad value refuses the whole report) so Invardia can answer `supersededBy`. Anonymous never carries it.
        $lid = if ($License) { "$($License.LicenseId)".Trim().ToLowerInvariant() } else { '' }
        if ($hb -and $sender.Mode -eq 'identified' -and $lid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            $hb | Add-Member -NotePropertyName 'LicenceId' -NotePropertyValue $lid -Force
        }
        if ($hb -and $sender.Mode -eq 'identified' -and $eps.Count) { $hb | Add-Member -NotePropertyName 'Endpoints' -NotePropertyValue ([object[]]$eps) -Force }
        # PIM 100.102: ActiveGuards -- the IDENTIFIED heartbeat (sent with the install key) ALWAYS carries it once the state was
        # read ([] = nothing is held), and NEVER when it was not read -- under PowerShell 7 (Test-PimUplink reads the JSON text).
        # DECISION (owner side, 2026-10-12): under Windows PowerShell 5.1 the field is NOT sent. WHY: 5.1's ConvertTo-Json writes
        # the list as {"value":[..],"Count":n} through the framework sender -- four forms tried on the test VM that day (a
        # New-Object array + Add-Member, a .NET array + Add-Member, a .NET array as a note property, an ArrayList as a note
        # property) -- and Invardia refuses the WHOLE heartbeat on a malformed list. WHAT HAPPENS: the heartbeat goes without
        # the field (the contract: left out = nothing changes) with ONE warning; the 'cleared' records go on both hosts.
        # Every hosted engine runs PowerShell 7 (containers); 5.1 is the test host and old layouts only.
        $agOnHb = $false
        if ($hb -and $sender.Mode -eq 'identified' -and $guardsKnown) {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                Write-Warning '[uplink] ActiveGuards is not sent from this host (Windows PowerShell 5.1 cannot write it as a JSON array) -- the heartbeat goes without it.'
            } else {
                $agItems = New-Object System.Collections.ArrayList
                foreach ($agOne in $activeNow) { [void]$agItems.Add($agOne) }
                $hb.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new('ActiveGuards', $agItems))
                # PROVE the text before it leaves (the same serialisation as the send): a JSON array, else the field is left
                # out (= nothing changes at Invardia; never a bad list).
                $agText = { param($rec) $t = ''; try { $t = "$($rec | ConvertTo-Json -Depth 6 -Compress)" } catch { $t = '' }; [bool]($t.Contains('"ActiveGuards":[')) }
                $agOnHb = [bool](& $agText $hb)
                if (-not $agOnHb) {
                    $hb.PSObject.Properties.Remove('ActiveGuards')
                    Write-Warning '[uplink] ActiveGuards could not be written as a JSON array -- the heartbeat goes without it.'
                }
            }
        }
        # Lane repfix (additive, IDENTIFIED heartbeat only): InstallRole single | managing | managed (+ ManagingTenantId for a
        # managed installation, when known) and the setup Controls with EVERY heartbeat (PIM 100.103), each with checkedUtc and,
        # for unknown, its reason. Controls ride the setup report's own switch (-SetupEnabled) and its id list (-SetupExtended).
        $hbAdd = @()
        if ($hb -and $isId -and $addState.on) {
            try {
                $ir = Get-PimUplinkInstallRole -ScenarioRole $ScenarioRole -ManagingTenantId $ManagingTenantId -TenantId $TenantId
                if ("$($ir.role)") {
                    $hb | Add-Member -NotePropertyName 'InstallRole' -NotePropertyValue "$($ir.role)" -Force; $hbAdd += 'InstallRole'
                    if ("$($ir.managingTenantId)") { $hb | Add-Member -NotePropertyName 'ManagingTenantId' -NotePropertyValue "$($ir.managingTenantId)" -Force; $hbAdd += 'ManagingTenantId' }
                }
            } catch { }
            # framework §12.11a MAIL-3 item 4 / PIM 100.145: EnvironmentName = the name the Manager header shows (pim.Settings
            # 'EnvironmentName'), so Invardia shows the same name as the mail subjects. Left out when none is set (never the
            # tenant id); additive, so a platform that does not know it yet takes the heartbeat without it.
            try {
                $envSet = & $GetSetting 'EnvironmentName'
                $envHb = if ($envSet -is [string]) { $envSet } elseif ($envSet -and $envSet.PSObject.Properties['name']) { "$($envSet.name)" } else { '' }
                $envHb = ("$envHb" -replace '\s+', ' ').Trim()
                if ($envHb.Length -gt 100) { $envHb = $envHb.Substring(0, 100).Trim() }
                if ($envHb) { $hb | Add-Member -NotePropertyName 'EnvironmentName' -NotePropertyValue $envHb -Force; $hbAdd += 'EnvironmentName' }
            } catch { }
            # framework §12.11b GUARD-STRICT item 5 (CR4): GuardMode on the identified heartbeat, so Invardia shows it; additive
            # (a refusal drops it for 24 h); left out when the mode cannot be read. The contract (Invardia 2026-10-14): the plain
            # word "normal", and while Strict the OBJECT { mode = "Strict"; until = <UTC>; startedBy = <the release version> } --
            # so the page and mails say until when and after which release.
            try {
                if (Get-Command Get-PimGuardStrictState -ErrorAction SilentlyContinue) {
                    $gmS = Get-PimGuardStrictState
                    if (-not "$($gmS.readError)".Trim()) {
                        $gmV = if ($gmS.active) { [pscustomobject][ordered]@{ mode = 'Strict'; until = "$($gmS.untilUtc)"; startedBy = "$($gmS.version)" } } else { 'normal' }
                        $hb | Add-Member -NotePropertyName 'GuardMode' -NotePropertyValue $gmV -Force; $hbAdd += 'GuardMode'
                    }
                }
            } catch { }
            if ($SetupEnabled -and $null -ne $SetupFacts) {
                $ctl = @(); try { $ctl = @(ConvertTo-PimUplinkHeartbeatControls -Facts $SetupFacts -Extended:$SetupExtended -NowUtc $NowUtc) } catch { $ctl = @() }
                if ($ctl.Count) {
                    # the same form as Endpoints (a JSON array under Windows PowerShell 5.1 too, Test-PimUplink AG18b); the
                    # text is PROVEN before it leaves -- not an array = the field is left out, never a bad list
                    $hb | Add-Member -NotePropertyName 'Controls' -NotePropertyValue ([object[]]$ctl) -Force
                    $ctlText = ''; try { $ctlText = "$($hb | ConvertTo-Json -Depth 6 -Compress)" } catch { $ctlText = '' }
                    if ($ctlText.Contains('"Controls":[{')) { $hbAdd += 'Controls' }
                    else { $hb.PSObject.Properties.Remove('Controls'); Write-Warning '[uplink] Controls could not be written as a JSON array -- the heartbeat goes without it.' }
                }
            }
            # §33.0 MORE TELEMETRY: the structured fields (Security, Collections, Jobs, Convergence, Mail, UpdatePending,
            # SqlAccess, FeaturesChanged) -- each behind its own switch (ON by default, 0/false/off/no = off), built ONCE per due identified
            # heartbeat by -StateFields, additive (a refusal naming one holds just that one 24 h; naming none holds them all). A throw = none of them.
            if ($StateFields) {
                $sfMap = $null; try { $sfMap = & $StateFields } catch { $sfMap = $null; Write-Warning "[uplink] the structured fields could not be built: $($_.Exception.Message)" }
                $sfMap = @($sfMap | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -First 1
                if ($sfMap) { try { foreach ($sfn in @(Add-PimUplinkStateFields -Record $hb -Fields $sfMap)) { $hbAdd += $sfn } } catch { Write-Warning "[uplink] the structured fields could not be added: $($_.Exception.Message)" } }
            }
        }
        # PIM 100.167 / framework 8.16: Capabilities + Licences -- identified only, the cause switch on, ONE probe per heartbeat.
        # Licences go as a JSON array, PROVEN in the text before it leaves (the ActiveGuards lesson): not an array = left out.
        $hbCause = @()
        if ($hb -and $isId -and $causeState.on) {
            # a name of its own: the probe is a plain scriptblock read through dynamic scope -- a local '$skus' here would
            # shadow a caller's '$skus' inside it (the test's stub returned $null that way)
            $tenantSkuList = $null
            if ($LicenceProbe) { try { $tenantSkuList = @(& $LicenceProbe) } catch { $tenantSkuList = $null } }
            try {
                $tc = Get-PimUplinkTenantCapabilities -Skus $tenantSkuList -HybridAd $HybridAd
                if (@($tc.capabilities.Keys).Count) { $hb | Add-Member -NotePropertyName 'Capabilities' -NotePropertyValue ([pscustomobject]$tc.capabilities) -Force; $hbCause += 'Capabilities' }
                if (@($tc.licences).Count) {
                    $hb | Add-Member -NotePropertyName 'Licences' -NotePropertyValue ([object[]]@($tc.licences)) -Force
                    $lt = ''; try { $lt = "$($hb | ConvertTo-Json -Depth 6 -Compress)" } catch { $lt = '' }
                    if ($lt.Contains('"Licences":[')) { $hbCause += 'Licences' } else { $hb.PSObject.Properties.Remove('Licences') }
                }
            } catch { Write-Warning "[uplink] Capabilities / Licences could not be built: $($_.Exception.Message)" }
        }
        # PIM 100.158 CR3: wave / releaseMode -- identified only, the switch on, only the keys that are known (a key with $null
        # = recorded and none, sent as JSON null); lower-case names, as SI sends them.
        $hbRc = @()
        if ($hb -and $isId -and $rcState.on -and $null -ne $ReleaseControlFields) {
            foreach ($rk in @('wave', 'releaseMode')) {
                if ($ReleaseControlFields.Contains($rk)) { $hb | Add-Member -NotePropertyName $rk -NotePropertyValue $ReleaseControlFields[$rk] -Force; $hbRc += $rk }
            }
        }
        $r = & $postRc $hb $hbAdd @{} $hbCause $hbRc
        if ("$($r.Status)" -eq 'ok') { $sent++; $hbSent = $true; $lastHb = $NowUtc.ToString('o') } else { $failed++; $stopped = $true; $why += "heartbeat: $($r.Reason)" }
        if ("$($r.Status)" -eq 'ok' -and $agOnHb) {
            foreach ($a in $activeNow) { if (-not $reported.ContainsKey("$($a.id)")) { $reported["$($a.id)"] = @{ sinceUtc = $NowUtc.ToString('o'); hold = $false } } }
        }
        # §100.39: Invardia re-issued the installed licence -> keep its successor's id for the licence-request job. Only a
        # well-formed id is kept; a missing / malformed answer changes nothing; nothing here can fail the cycle.
        if ("$($r.Status)" -eq 'ok') {
            try {
                $sup = ''; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains('Body')) { $sup = Get-PimUplinkSupersededBy -Body $r['Body'] } }
                           elseif ($r.PSObject.Properties['Body']) { $sup = Get-PimUplinkSupersededBy -Body $r.Body }
                if ($sup) {
                    $prevSup = ''; try { $pv = & $GetSetting 'LicenceSupersededBy'; if ($pv -is [string]) { $prevSup = $pv.Trim() } } catch { }
                    if ($prevSup -ne $sup) { & $SetSetting 'LicenceSupersededBy' $sup }
                    $supNote = "; Invardia re-issued the licence (superseded by $sup) -- the licence request asks for it"
                }
            } catch { $supNote = "" }
            # PIM 100.167 (lane G): Invardia's id of this environment, when its answer carries one -> pim.Settings
            # 'InvardiaEnvironmentId' (the customer alert mail links the environment's portal page with it). Written only
            # when it changes; a missing / malformed answer changes nothing.
            try {
                $envBody = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains('Body')) { $envBody = $r['Body'] } } elseif ($r.PSObject.Properties['Body']) { $envBody = $r.Body }
                $envId = Get-PimUplinkEnvironmentId -Body $envBody
                if ($envId) {
                    $prevEnv = ''; try { $pe = & $GetSetting 'InvardiaEnvironmentId'; if ($pe -is [string]) { $prevEnv = $pe.Trim().ToLowerInvariant() } } catch { }
                    if ($prevEnv -ne $envId) { & $SetSetting 'InvardiaEnvironmentId' $envId }
                }
            } catch { }
        }
    }
    # PIM 100.10 (framework 8.7): the SETUP report -- identified only (anonymous Community sends nothing of this), its own
    # switch, once a day and on every change of state. Its state (UplinkSetupState) moves only when the report landed.
    $setupSent = $false
    if (-not $stopped -and $SetupEnabled -and $sender.Mode -eq 'identified' -and $null -ne $SetupFacts -and (Get-Command New-PimSetupReport -ErrorAction SilentlyContinue)) {
        $sst = $null; try { $sst = & $GetSetting 'UplinkSetupState' } catch { $sst = $null }
        if ($sst -is [string]) { try { $sst = $sst | ConvertFrom-Json } catch { $sst = $null } }
        $prevSince = $null; if ($sst -and $sst.PSObject.Properties['since']) { $prevSince = $sst.since }
        $edition = Get-PimUplinkEdition -License $License -ProHere $ProHere
        $rep = New-PimSetupReport -Facts $SetupFacts -Product $script:PimUplinkProduct -Version $Version -Ring $Ring -Edition $edition -Extended:$SetupExtended -PreviousSince $prevSince -NowUtc $NowUtc
        if (Get-PimSetupReportDue -State $sst -Fingerprint $rep.fingerprint -NowUtc $NowUtc) {
            $r = & $post $rep.record
            if ("$($r.Status)" -eq 'ok') {
                $sent++; $setupSent = $true
                & $SetSetting 'UplinkSetupState' ([pscustomobject][ordered]@{ lastSentUtc = $NowUtc.ToString('o'); fingerprint = $rep.fingerprint; extended = [bool]$SetupExtended; since = [pscustomobject]$rep.since })
            } else { $failed++; $stopped = $true; $why += "setup: $($r.Reason)" }
        }
    }
    # PIM 100.103 (b): the updater's own run ("nothing to do" included) is one more run -- job 'pim-update', additive.
    $planRuns = @($Runs)
    if ($addState.on -and $null -ne $UpdateRun) { $planRuns = @($planRuns) + @($UpdateRun) }
    $plan = Get-PimUplinkRunPlan -Runs $planRuns -SinceUtc $floor -SinceByJob $marks
    $left = 0
    foreach ($p in @($plan.reports)) {
        # STOP at the first failure (a 429 says "wait") and at the per-cycle budget: the rest keep their watermark.
        if ($stopped -or $sent -ge $budget) { $left++; continue }
        # PIM 100.143: a class the plan already knows (RUN-NO-RESULT) wins; otherwise a failure's text is classified.
        $cls = if ($p.ContainsKey('errorClass') -and "$($p.errorClass)") { "$($p.errorClass)" } elseif ($p.outcome -eq 'failed') { Get-PimUplinkErrorClass -Text $p.errorText } else { '' }
        $rec = New-AitUplinkReport -Kind run @common -Job $p.job -Outcome $p.outcome -DurationMs $p.durationMs -ErrorClass $cls -ErrorText $p.errorText `
                 -Counts @{ runs = $p.runCount }
        # 100.34: fixKind beside the class -- added HERE, not in the framework client (sync/_AitUplink.ps1 must stay
        # byte-identical), and only behind PIM_UPLINK_FIXKIND until Invardia's schema has the field.
        # §100.45: only a FAILED report carries FixKind -- a throttled warning is not a defect to fix, so it never opens one.
        if ($rec -and $cls -and $FixKind -and $p.outcome -eq 'failed') { $rec | Add-Member -NotePropertyName 'FixKind' -NotePropertyValue (Get-PimUplinkFixKind -ErrorClass $cls) -Force }
        # Lane repfix (additive): Outcome ok | warning | held | failed + ActionBy by Get-PimUplinkOutcomeAction (100.99 /
        # 100.111), what a held / warning run said (ErrorText, identified), UpdateAction on the updater's run, and the
        # customer-ready Solution of the class (100.115, identified: it names the item). -legacy = the record as it was.
        $addNames = @(); $addLegacy = @{}
        if ($rec -and $addState.on) {
            try {
                # a removal that did not happen keeps the run failed: the currently-failing REMOVE items of the run's classes
                $notRemoved = 0
                if ("$($p.outcome)" -eq 'failed') {
                    $runCodes = @(Get-PimUplinkFailureCodes -Text "$($p.errorText)")
                    $notRemoved = @(@($EngineFailures) | Where-Object { $null -ne $_ -and "$($_.op)".Trim() -match '^(?i)remove' -and ($runCodes -contains "$($_.code)".Trim().ToUpperInvariant()) }).Count
                }
                $oa = Get-PimUplinkOutcomeAction -LegacyOutcome "$($p.outcome)" -Kind "$($p.kind)" -Text "$($p.errorText)" -ErrorClass $cls -WarningKind "$($p.warningKind)" -NotRemoved $notRemoved
                if ("$($oa.outcome)" -ne "$($rec.Outcome)") {
                    $addLegacy['Outcome'] = "$($rec.Outcome)"
                    $rec | Add-Member -NotePropertyName 'Outcome' -NotePropertyValue "$($oa.outcome)" -Force; $addNames += 'Outcome'
                }
                $rec | Add-Member -NotePropertyName 'ActionBy' -NotePropertyValue "$($oa.actionBy)" -Force; $addNames += 'ActionBy'
                if ("$($p.updateAction)" -in @('none', 'built', 'rolled', 'schema', 'failed')) { $rec | Add-Member -NotePropertyName 'UpdateAction' -NotePropertyValue "$($p.updateAction)" -Force; $addNames += 'UpdateAction' }
                $solCode = "$cls".Trim().ToUpperInvariant()
                if (-not $solCode -and "$($p.kind)" -eq 'held') {
                    # a policy change set held for approval names its provider, not a class: the class of that hold
                    if ("$($p.noteText)" -match 'GroupsPolicies') { $solCode = 'GROUP-POLICY-MASS-HOLD' } elseif ("$($p.noteText)" -match 'EntraRolePolicies') { $solCode = 'ENTRA-POLICY-MASS-HOLD' } elseif ("$($p.noteText)" -match 'AzResPolicies') { $solCode = 'AZ-POLICY-MASS-HOLD' }
                    if ($solCode) { $rec | Add-Member -NotePropertyName 'ErrorClass' -NotePropertyValue $solCode.ToLowerInvariant() -Force; $addNames += 'ErrorClass' }
                }
                if ($isId) {
                    if (-not $rec.PSObject.Properties['ErrorText'] -and "$($p.noteText)".Trim()) {
                        $nt = & $redact "$($p.noteText)" 8000
                        if ($nt) { $rec | Add-Member -NotePropertyName 'ErrorText' -NotePropertyValue $nt -Force; $addNames += 'ErrorText' }
                    }
                    if ($solCode -and (Get-Command Get-PimFailureSolution -ErrorAction SilentlyContinue)) {
                        $labels = @(@($EngineFailures) | Where-Object { $null -ne $_ -and "$($_.code)".Trim().ToUpperInvariant() -eq $solCode } |
                                    ForEach-Object { if ("$($_.label)".Trim()) { "$($_.label)".Trim() } else { "$($_.key)".Trim() } } | Where-Object { $_ })
                        $sol = Get-PimFailureSolution -Code $solCode -Items $labels
                        if ($sol) { $st0 = & $redact "$($sol.text)" 2000; if ($st0) { $rec | Add-Member -NotePropertyName 'Solution' -NotePropertyValue $st0 -Force; $addNames += 'Solution' } }
                    }
                }
            } catch { Write-Warning "[uplink] the additive fields of $($p.job) could not be built: $($_.Exception.Message)" }
        }
        # PIM 100.167 / framework 8.16: Reports[] -- every cause the run names, with its stable code (the cause switch on).
        $runCause = @()
        if ($rec -and $causeState.on) {
            try {
                $ci = @(New-PimUplinkCauseReports -Plan $p -ErrorClass $cls -EngineFailures $EngineFailures -Identified $isId -Redact $redact)
                if ($ci.Count) {
                    $rec | Add-Member -NotePropertyName 'Reports' -NotePropertyValue ([object[]]$ci) -Force
                    $rt = ''; try { $rt = "$($rec | ConvertTo-Json -Depth 6 -Compress)" } catch { $rt = '' }
                    if ($rt.Contains('"Reports":[{')) { $runCause += 'Reports' }
                    else { $rec.PSObject.Properties.Remove('Reports'); Write-Warning "[uplink] Reports of $($p.job) could not be written as a JSON array -- the record goes without it." }
                }
            } catch { Write-Warning "[uplink] the causes of $($p.job) could not be built: $($_.Exception.Message)" }
        }
        $r = & $postCause $rec $addNames $addLegacy $runCause
        if ("$($r.Status)" -eq 'ok') { $sent++; $marks[$p.job] = $p.finishedUtc }
        else { $failed++; $stopped = $true; $left++; $why += "$($p.job): $($r.Reason)" }
    }
    # GUARD-1 (framework, 2026-10-04): every guard whose last trip is newer than its last send goes as a Kind 'guard' record
    # (PIM-Guard.ps1). Invardia opens / updates the support ticket from it. Same budget and stop-at-first-failure as the runs.
    $guardsSent = 0
    $dueIds = @{}   # PIM 100.102: guards whose newest trip is not sent yet -- never reported 'cleared' in the same cycle
    if (Get-Command Select-PimGuardTelemetryDue -ErrorAction SilentlyContinue) {
        $gs = $null; try { $gs = & $GetSetting 'GuardTrips' } catch { $gs = $null }
        if ($gs -is [string]) { try { $gs = $gs | ConvertFrom-Json } catch { $gs = $null } }
        $dueList = @(); try { $dueList = @(Select-PimGuardTelemetryDue -State $gs) } catch { $dueList = @() }
        foreach ($e in $dueList) { $did = Get-PimUplinkGuardId (Get-PimUplinkField $e 'guardId'); if ($did) { $dueIds[$did] = $true } }
        if (-not $stopped) {
            foreach ($e in $dueList) {
                if ($stopped -or $sent -ge $budget) { $left++; continue }
                $rec = New-PimGuardUplinkRecord -Entry $e -Mode $sender.Mode -Product $script:PimUplinkProduct -Version $Version -Ring $Ring -InstallId $iid -TenantId $TenantId -ManagerUrl $mgrBase
                if (-not $rec) { continue }
                # Lane repfix (additive): Outcome + ActionBy on the guard record (Get-PimUplinkGuardOutcomeAction); the
                # existing GuardOutcome / Severity are unchanged beside them.
                $gNames = @()
                if ($addState.on) {
                    $ga = Get-PimUplinkGuardOutcomeAction -GuardOutcome "$($rec.GuardOutcome)" -ActionText "$(Get-PimUplinkField $e 'actionText')"
                    $rec | Add-Member -NotePropertyName 'Outcome' -NotePropertyValue "$($ga.outcome)" -Force
                    $rec | Add-Member -NotePropertyName 'ActionBy' -NotePropertyValue "$($ga.actionBy)" -Force
                    $gNames = @('Outcome', 'ActionBy')
                }
                $r = & $postAdd $rec $gNames @{}
                if ("$($r.Status)" -eq 'ok') {
                    $sent++; $guardsSent++; $e | Add-Member -NotePropertyName lastSentUtc -NotePropertyValue $NowUtc.ToString('o') -Force
                    # reported as tripped: it gets its 'cleared' record on a later cycle, once it is no longer held
                    if (-not $reported.ContainsKey("$($rec.GuardId)")) { $reported["$($rec.GuardId)"] = @{ sinceUtc = $NowUtc.ToString('o'); hold = $false } }
                }
                else { $failed++; $stopped = $true; $left++; $why += "guard $($e.guardId): $($r.Reason)" }
            }
            if ($guardsSent) { try { & $SetSetting 'GuardTrips' $gs } catch { $why += "guard send marks not saved: $($_.Exception.Message)" } }
        }
    }
    # PIM 100.102: ONE 'cleared' record per guard that was reported (tripped / active) and is not held any more. Only when
    # the state was read. Same budget and stop-at-first-failure as above; a record that did not land keeps its id for the
    # next cycle (never lost), a record that landed drops it (never sent twice).
    $clearedSent = 0
    if ($guardsKnown) {
        foreach ($hid in @($holdIds.Keys)) { if ($reported.ContainsKey("$hid")) { $reported["$hid"].hold = $true } }
        foreach ($cid in @($reported.Keys | Sort-Object)) {
            if ($activeIds.ContainsKey("$cid") -or $dueIds.ContainsKey("$cid")) { continue }
            if ($stopped -or $sent -ge $budget) { $left++; continue }
            $trip = $null; if ($tripBy.ContainsKey("$cid")) { $trip = $tripBy["$cid"] }
            $since = Get-PimUplinkField $trip 'lastSeenUtc'
            if (-not (ConvertTo-PimUplinkUtc $since)) { $since = $reported["$cid"].sinceUtc }
            $by = Get-PimUplinkGuardClearedBy -GuardId "$cid" -WasHold ([bool]$reported["$cid"].hold) -Releases $gState.releases -ReleasesKnown ($null -ne $gState.releases) -SinceUtc $since -NowUtc $NowUtc
            $rec = New-PimUplinkGuardClearedRecord -GuardId "$cid" -Mode $sender.Mode -Product $script:PimUplinkProduct -Version $Version -Ring $Ring -InstallId $iid -TenantId $TenantId `
                     -ClearedBy $by -Job "$(Get-PimUplinkField $trip 'job')" -NowUtc $NowUtc
            if (-not $rec) { $reported.Remove("$cid"); continue }
            $cNames = @()
            if ($addState.on) {   # lane repfix: a guard that is clear again = ok, nobody has to act
                $rec | Add-Member -NotePropertyName 'Outcome' -NotePropertyValue 'ok' -Force
                $rec | Add-Member -NotePropertyName 'ActionBy' -NotePropertyValue 'none' -Force
                $cNames = @('Outcome', 'ActionBy')
            }
            $r = & $postAdd $rec $cNames @{}
            if ("$($r.Status)" -eq 'ok') { $sent++; $clearedSent++; $reported.Remove("$cid") }
            else { $failed++; $stopped = $true; $left++; $why += "guard $cid cleared: $($r.Reason)" }
        }
    }
    $msg = "$($sender.Mode): $sent sent$(if ($guardsSent) { " ($guardsSent guard record(s))" })$(if ($clearedSent) { " ($clearedSent guard(s) reported clear)" })$(if ($setupSent) { ' (setup report)' })$(if ($failed) { ", $failed failed -- $(@($why | Select-Object -First 3) -join '; ')" })$(if ($left) { ", $left left for the next cycle" })$supNote"
    # §33.0 BUG (2026-10-16): the refusal names its record (kind, job, HTTP status, Invardia's answer), and while a hold lasts
    # every cycle says so, whichever caller set it. A failure to build the text keeps the plain sentence.
    $refText = { param($st, $what) $t = ''; try { if ($null -ne $st.info) { $t = " ($(Format-PimUplinkRefusalLine -What $what -Info $st.info))" } } catch { $t = '' }; $t }
    # 2.4.644: the per-field additive hold -- which fields it holds now (this cycle's named ones + a hold still running); a
    # whole-group refusal (nothing named) wins and stores no list (= every additive field held, as before).
    $addFieldsOut = @()
    if (-not $addState.whole) {
        if ($addState.refusedNow) { $addFieldsOut = @(@($(if ($addPartial) { $addPrevFields })) + @($addState.fields) | Where-Object { "$_" } | Select-Object -Unique) }
        elseif ($addPartial) { $addFieldsOut = @($addPrevFields) }
    }
    if ($addState.refusedNow -and $addState.whole) { $msg += "; Invardia refused the new report fields -- sent in the old form, tried again in 24 h$(& $refText $addState 'new report fields')" }
    elseif ($addState.refusedNow) { $msg += "; Invardia refused $(@($addState.fields) -join ', ') -- sent without $(if (@($addState.fields).Count -eq 1) { 'it' } else { 'them' }) (the other new report fields still go), tried again in 24 h$(& $refText $addState (& $addWhat $addState.fields))" }
    if ($causeState.refusedNow) { $msg += "; Invardia refused the cause fields (Reports / Capabilities / Licences) -- sent without them, tried again in 24 h$(& $refText $causeState 'cause fields')" }
    if ($rcState.refusedNow) { $msg += "; Invardia refused the release-control fields (wave / releaseMode) -- sent without them, tried again in 24 h$(& $refText $rcState 'release-control fields')" }
    try {
        if (-not $addState.refusedNow -and $addHeld) { $msg += Format-PimUplinkHeldNote -What (& $addWhat $addPrevFields) -Prefix 'additiveRefused' -State $state -RefusedUtc $addPrev }
        if (-not $causeState.refusedNow -and $causeHeld) { $msg += Format-PimUplinkHeldNote -What 'cause fields (Reports / Capabilities / Licences)' -Prefix 'causesRefused' -State $state -RefusedUtc $causePrev }
        if (-not $rcState.refusedNow -and $rcHeld) { $msg += Format-PimUplinkHeldNote -What 'release-control fields (wave / releaseMode)' -Prefix 'releaseControlRefused' -State $state -RefusedUtc $rcPrev }
    } catch { }
    $newState = [ordered]@{ mode = $sender.Mode; lastHeartbeatUtc = $lastHb; runWatermarkUtc = $floor; jobMarks = [pscustomobject]$marks
                            consent = $consent; lastCycleUtc = $NowUtc.ToString('o'); lastResult = $msg
                            # PIM 100.75: read by the end-of-install verify (Confirm-PimInstall 'telemetry')
                            lastFailed = $failed }
    # PIM 100.102: the reported set. Left out while it was never started AND the state could not be read (so the first
    # readable cycle still starts it from the sent trip records).
    if ($hadReported -or $guardsKnown) {
        $repOut = [ordered]@{}
        foreach ($rid0 in @($reported.Keys | Sort-Object)) { $repOut["$rid0"] = [pscustomobject][ordered]@{ sinceUtc = "$($reported["$rid0"].sinceUtc)"; hold = [bool]$reported["$rid0"].hold } }
        $newState['guardsReported'] = [pscustomobject]$repOut
    }
    # Lane repfix: when Invardia refused the additive fields (kept for 24 h, then they are tried again).
    if ($addState.refusedNow) { $newState['additiveRefusedUtc'] = $NowUtc.ToString('o') }
    elseif ($addHeld) { $apu = ConvertTo-PimUplinkUtc $addPrev; if ($apu) { $newState['additiveRefusedUtc'] = $apu.ToString('o') } }
    # 2.4.644: the hold names the fields it holds ("SqlAccess" / "SqlAccess,Security"); absent = the whole additive group.
    if ($newState.Contains('additiveRefusedUtc') -and $addFieldsOut.Count) { $newState['additiveRefusedFields'] = (@($addFieldsOut) -join ',') }
    # PIM 100.167: the cause fields' own hold (left out entirely while the switch was never refused -- the state stays as before)
    if ($causeState.refusedNow) { $newState['causesRefusedUtc'] = $NowUtc.ToString('o') }
    elseif ($causeHeld) { $cpu = ConvertTo-PimUplinkUtc $causePrev; if ($cpu) { $newState['causesRefusedUtc'] = $cpu.ToString('o') } }
    # PIM 100.158: the release-control fields' own hold (left out while never refused)
    if ($rcState.refusedNow) { $newState['releaseControlRefusedUtc'] = $NowUtc.ToString('o') }
    elseif ($rcHeld) { $rpu = ConvertTo-PimUplinkUtc $rcPrev; if ($rpu) { $newState['releaseControlRefusedUtc'] = $rpu.ToString('o') } }
    # §33.0 BUG (2026-10-16): beside each hold, WHAT was refused (...RefusedKind / Job / Status / Reason) -- this cycle's, else
    # the stored one while the hold lasts. A failure here never stops the state (the hold itself is written above).
    try { Set-PimUplinkRefusalState -State $newState -Prefix 'additiveRefused' -Info $(if ($addState.refusedNow) { $addState.info }) -Previous $state -Carry ([bool]$addHeld) } catch { Write-Warning "[uplink] the additive refusal record was not saved: $($_.Exception.Message)" }
    try { Set-PimUplinkRefusalState -State $newState -Prefix 'causesRefused' -Info $(if ($causeState.refusedNow) { $causeState.info }) -Previous $state -Carry ([bool]$causeHeld) } catch { Write-Warning "[uplink] the cause refusal record was not saved: $($_.Exception.Message)" }
    try { Set-PimUplinkRefusalState -State $newState -Prefix 'releaseControlRefused' -Info $(if ($rcState.refusedNow) { $rcState.info }) -Previous $state -Carry ([bool]$rcHeld) } catch { Write-Warning "[uplink] the release-control refusal record was not saved: $($_.Exception.Message)" }
    & $SetSetting 'UplinkState' ([pscustomobject]$newState)
    return @{ ran = $true; mode = $sender.Mode; sent = $sent; failed = $failed; left = $left; heartbeat = $hbSent; setup = $setupSent; message = $msg; reasons = @($why)
              additive = [bool]$addState.on; additiveRefused = [bool]$addState.refusedNow; additiveHeldFields = @($addFieldsOut)
              causes = [bool]$causeState.on; causesRefused = [bool]$causeState.refusedNow
              releaseControl = [bool]$rcState.on; releaseControlRefused = [bool]$rcState.refusedNow
              guardsCleared = $clearedSent; activeGuards = $(if ($guardsKnown) { $activeNow.Count } else { -1 }) }
}

function Get-PimUplinkDeliveryWarning {
    <#
      PURE. PIM 100.75 (HOGYM managed install 2026-10-11: NO telemetry arrived at Invardia and nobody could see why -- the
      uplink job never threw, so every run was recorded green). Is this uplink run a WARNING, and what does it say?
        -Enabled         the feature 'telemetry.uplink'                 (off -> never a warning; the opt-out is its own report)
        -Cycle           Invoke-PimUplinkCycle's result                 (mode, failed, reasons)
        -StoredKeyRaw    pim.Settings 'InvardiaInstallKey' as stored    ('' = none stored)
        -ResolvedKey     Resolve-PimInvardiaInstallKey                  ('' = none usable: missing or malformed)
        -LicenceRegistered  a Pro / trial / MSP licence is registered for this tenant
        -ClaimState      pim.Settings 'InstallKeyClaimState'            (the install-key job's last answer, named in the text)
      Returns @{ warning; kind; reason; note; summary }:
        kind     send-failed | key-malformed | key-missing | not-identified (joined with '+' when several hold)
        reason   "telemetry not delivered: <Invardia's 422 field list / the transport error>" and / or the key sentence
        note     the key sentence alone (shown in the run detail even when nothing else is wrong)
        summary  a STABLE sentence per kind (no counts, no times) -- the alert's text, so the alert path's identical-alert
                 debounce (1440 min) sends it at most once a day while it lasts
      A telemetry problem is never a failed run (framework 12.18 / 12.21). Never throws.
    #>
    param([bool]$Enabled, [AllowNull()][object]$Cycle, [string]$StoredKeyRaw = '', [string]$ResolvedKey = '',
          [bool]$LicenceRegistered = $false, [AllowNull()][object]$ClaimState = $null)
    $out = [ordered]@{ warning = $false; kind = ''; reason = ''; note = ''; summary = '' }
    try {
        if (-not $Enabled -or $null -eq $Cycle) { return [pscustomobject]$out }
        $mode = "$(Get-PimUplinkField $Cycle 'mode')".Trim()
        if ($mode -eq 'disabled') { return [pscustomobject]$out }
        $failed = 0; try { $failed = [int](Get-PimUplinkField $Cycle 'failed') } catch { $failed = 0 }
        $reasons = @(@(Get-PimUplinkField $Cycle 'reasons') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $raw = "$StoredKeyRaw".Trim().Trim('"'); $key = "$ResolvedKey".Trim()
        $kinds = New-Object System.Collections.Generic.List[string]
        $texts = New-Object System.Collections.Generic.List[string]
        $sums  = New-Object System.Collections.Generic.List[string]
        if ($failed -gt 0) {
            $kinds.Add('send-failed')
            $why = if ($reasons.Count) { @($reasons | Select-Object -First 3) -join '; ' } else { "$failed report(s) were refused or could not be sent" }
            $texts.Add("telemetry not delivered: $why")
            $sums.Add('Telemetry to Invardia is not being delivered: the uplink refused the reports or could not be reached.')
        }
        $claim = ''
        if ($ClaimState) {
            $ca = "$(Get-PimUplinkField $ClaimState 'action')".Trim(); $cm = "$(Get-PimUplinkField $ClaimState 'message')".Trim()
            if ($ca -and $ca -ne 'claimed') { $claim = " (the last claim: $ca$(if ($cm) { " -- $cm" }))" }
        }
        if (-not $key) {
            if ($raw) {
                $kinds.Add('key-malformed')
                $out.note = "an install key is stored but it is not a valid Invardia install key -- telemetry is anonymous; the engine claims one every 6 h$claim"
                $sums.Add('Telemetry to Invardia is anonymous: the stored install key is not valid.')
            } elseif ($LicenceRegistered) {
                $kinds.Add('key-missing')
                $out.note = "no install key stored -- telemetry is anonymous; the engine claims one every 6 h$claim"
                $sums.Add('Telemetry to Invardia is anonymous: no install key is stored for this licensed install.')
            }
        } elseif ($mode -and $mode -ne 'identified') {
            $kinds.Add('not-identified')
            $out.note = "an install key is stored but telemetry ran '$mode' -- Invardia cannot tell which environment sent it"
            $sums.Add('Telemetry to Invardia is not identified although an install key is stored.')
        }
        if ($out.note) { $texts.Add($out.note) }
        if ($kinds.Count) {
            $out.warning = $true
            $out.kind = ($kinds.ToArray() -join '+')
            $out.reason = ($texts.ToArray() -join ' | ')
            $out.summary = ($sums.ToArray() -join ' ')
        }
    } catch { }
    return [pscustomobject]$out
}

function Invoke-PimUplinkJob {
    <#
      Job 'uplink' (hourly). Inert unless the feature 'telemetry.uplink' is ON. Key: $env:PIM_UPLINK_KEY (a Container Apps
      secret, never a file in the image, never returned by any API). Settings: UplinkState (shown on the Jobs page through
      the run detail), TelemetryInstallId, UplinkEndpoint (optional; default Invardia's).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          # PIM 100.167 (lane G, framework 8.16 "Order and links"): a FLUSH before a customer alert mail -- the job's own
          # cycle (same watermarks, so nothing is sent twice), a smaller budget and no pause between records.
          # 0 / -1 = the hourly job's own values.
          [int]$MaxPerCycle = 0, [int]$PauseMs = -1)
    $on = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.uplink' -Quiet))
    # §11: OFF still runs ONE check -- an install that was on and is now off reports its opt-out once (Invoke-PimUplinkCycle).
    # Never on = nothing is sent and nothing is called; no SQL store while off = nothing to check, quietly.
    $offDetail = "uplink: off (feature 'telemetry.uplink')"
    if (-not (Get-Command New-AitUplinkReport -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AitUplink.framework.ps1') }
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { if (-not $on) { return [pscustomobject]@{ ran = $false; whatIf = [bool]$WhatIf; detail = $offDetail } }; throw '[uplink] no SQL store -- the telemetry state cannot be read' }
    # PLAIN scriptblocks, never .GetNewClosure() (Test-PimHybridWorker L19): they read $cs / $WhatIf through dynamic scope.
    $get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $set = { param($n, $v) if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } }
    # §100.39: Send-PimUplinkRecord = the framework's Send-AitUplink, unchanged, plus the response body (supersededBy).
    $send = { param($rec, $ep, $code) if ($WhatIf) { @{ Status = 'ok'; Reason = 'what-if' } } else { Send-PimUplinkRecord -Record $rec -Endpoint $ep -AccessCode $code } }
    $sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $verFile = Join-Path $sol 'VERSION'
    $ver = if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } elseif ($env:PIM_VERSION) { "$env:PIM_VERSION" } else { '' }
    $tid = ''; if (Get-Command Resolve-PimLicenseTenantId -ErrorAction SilentlyContinue) { try { $tid = "$(Resolve-PimLicenseTenantId)" } catch { } }
    $lic = $null; try { $lic = Get-PimLicense } catch { $lic = $null }
    $proHere = $false; if ($lic -and (Get-Command Test-PimLicenseIsProForTenant -ErrorAction SilentlyContinue)) { try { $proHere = [bool](Test-PimLicenseIsProForTenant -License $lic -TenantId $tid).pro } catch { } }
    if (-not (Get-Command Resolve-PimUplinkRing -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-UplinkSetup.ps1') }
    # 100.10 (Invardia 2026-10-09: "update level unknown" for every PIM install -- Reports.Ring empty): PIM_UPDATE_RING is set on
    # the UPDATE job only, and this job runs in the tick job. The environment's own record (UpdateState) carries the ring too.
    $us = $null; $usRead = $false; try { $us = & $get 'UpdateState'; if ($us -is [string]) { $us = $us | ConvertFrom-Json }; $usRead = $true } catch { $us = $null }
    $ring = Resolve-PimUplinkRing -EnvRing "$env:PIM_UPDATE_RING" -UpdateState $us
    $rid = if ($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT) { 'mi-container' } else { 'spn-certificate' }
    $runs = @(); $runsRead = $false; if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { try { $runs = @(Get-PimJobRunHistory); $runsRead = $true } catch { $runs = @() } }
    $key = if (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue) { Resolve-PimInvardiaInstallKey -GetSetting $get } else { "$env:PIM_UPLINK_KEY" }
    # 100.10: the setup report -- its own switch (feature 'telemetry.setup', ON by default; it only ever sends with an install key).
    $setupOn = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.setup' -Quiet))
    $facts = $null
    if ($on -and $setupOn -and "$key".Trim()) {
        $msp = ''; $down = $null
        try { if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) { $sc = Get-PimActiveScenario; if ("$($sc.role)" -eq 'msp-managed') { $msp = 'Slave' } elseif ("$($sc.role)" -eq 'msp-master') { $msp = 'Master' } } } catch { }
        try { if ($msp -eq 'Slave' -and (Get-Command Test-PimFeatureEnabled -ErrorAction SilentlyContinue)) { $down = [bool](Test-PimFeatureEnabled -Key 'msp.downlink') } } catch { $down = $null }
        try { $facts = Get-PimSetupFacts -GetSetting $get -Runs $runs -License $lic -ProHere $proHere -InstallKey $key -MspRole $msp -DownlinkOn $down -NowUtc $NowUtc } catch { $facts = $null }
    }
    # 100.36: the SQL space for the IDENTIFIED heartbeat (the store's own MI connection); a failed read = both numbers left out.
    $sqlSpace = $null
    if ($on -and "$key".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) {
        $spaceSql = $script:PimUplinkSqlSpaceQuery
        $sqlSpace = Get-PimUplinkSqlSpace -Query { Invoke-PimSqlQuery -ConnectionString $cs -Sql $spaceSql }
    }
    # framework 8.11 ASSET-COUNTS: what the tick's tenant-cache refresh recorded (members / guests / service principals).
    $assets = $null
    try {
        $tc = & $get 'TenantObjectCounts'; if ($tc -is [string] -and "$tc".Trim()) { $tc = $tc | ConvertFrom-Json }
        if ($tc) {
            $assets = @{ users = $tc.Members; guests = $tc.Guests; servicePrincipals = $tc.ServicePrincipals; groups = $tc.Groups }
            # 100.128 (owner via Invardia 2026-10-13: the dashboard's Users = ALL user objects): usersTotal = every user
            # incl. disabled and guests; usersDisabled = total - enabled members - guests. Left out unless all three are numbers.
            $assets['usersTotal'] = $tc.Users
            $tu = 0L; $tm = 0L; $tg = 0L
            if ([long]::TryParse("$($tc.Users)", [ref]$tu) -and [long]::TryParse("$($tc.Members)", [ref]$tm) -and [long]::TryParse("$($tc.Guests)", [ref]$tg) -and ($tu - $tm - $tg) -ge 0) { $assets['usersDisabled'] = $tu - $tm - $tg }
        }
    } catch { $assets = $null }
    # PIM 100.56 / framework 8.9: the endpoints from what the environment already records (identified only; no ARM read).
    $endpoints = @()
    if ($on -and "$key".Trim()) { try { $endpoints = @(Get-PimUplinkEndpoints -GetSetting $get) } catch { $endpoints = @() } }
    # Lane repfix (additive, identified): the product's own role (the STORED scenario; unknown = left out), the managing
    # tenant of a managed installation (pim.Settings 'MspManagingTenantId' -- left out while nothing has recorded it), the
    # currently-failing items (their names fill the Solution text) and the updater's last run as a run of its own.
    $scRole = ''; $mgTid = ''; $engFails = @(); $updRun = $null
    if ($on -and "$key".Trim()) {
        $scRole = Resolve-PimUplinkScenarioRole -GetSetting $get
        if ($scRole -eq 'msp-managed') { try { $mgTid = "$(& $get 'MspManagingTenantId')".Trim() } catch { $mgTid = '' } }
    }
    # PIM 100.128: the adoption counts -- a PLAIN scriptblock (dynamic scope: $cs / $adMsp / $adHy), invoked by the cycle ONLY
    # when the identified heartbeat is due, so the COUNT queries run once an hour at most. Identified only (needs the key).
    $adoption = $null
    if ($on -and "$key".Trim() -and (Get-Command Invoke-PimSqlScalar -ErrorAction SilentlyContinue)) {
        $adMsp = ($scRole -eq 'msp-master')
        $adHy = $true
        try { if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) { $adHy = [bool](Test-PimFeatureAvailable -Key 'hybrid.ad' -Quiet) } } catch { $adHy = $false }
        # §33.0 MORE TELEMETRY: convergenceFailures24h from the run history this job already read ($null = not read = left out)
        $adRuns = $null; if ($runsRead) { $adRuns = [object[]]@($runs) }   # never `= if {}`: an empty list would unroll to $null
        $adoption = { Get-PimUplinkAdoptionCounts -Query { param($n, $s) Invoke-PimSqlScalar -ConnectionString $cs -Sql $s } -MspMaster:$adMsp -HybridAd:$adHy -Runs $adRuns -NowUtc $NowUtc }
    }
    if ($on) {
        try { $ef = & $get 'EngineItemFailures'; if ($ef -is [string] -and "$ef".Trim()) { $ef = $ef | ConvertFrom-Json }; $engFails = @(@($ef) | Where-Object { $null -ne $_ }) } catch { $engFails = @() }
        $updRun = ConvertTo-PimUplinkUpdateRun -UpdateState $us
    }
    # PIM 100.167 / framework 8.16: the cause fields -- feature 'telemetry.causes' (OFF by default until Invardia is live).
    # The licence probe is a PLAIN scriptblock (dynamic scope), invoked by the cycle only when the identified heartbeat is due.
    $causesOn = [bool]($on -and "$key".Trim() -and (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.causes' -Quiet))
    $licProbe = $null; $hyAd = $null
    if ($causesOn) {
        if (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) { $licProbe = { @(Invoke-PimGraph -Path '/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans' -All) } }
        try { if ([bool](Test-PimFeatureAvailable -Key 'hybrid.ad' -Quiet)) { $hyAd = $true } } catch { $hyAd = $null }
    }
    $cyc = @{}
    if ($MaxPerCycle -gt 0) { $cyc['MaxPerCycle'] = $MaxPerCycle }
    $pause = if ($WhatIf) { 0 } elseif ($PauseMs -ge 0) { $PauseMs } else { 2500 }
    # PIM 100.158 / framework 12.11e CR3: wave (what the updater was served, pim.Settings 'ReleaseWave') + releaseMode (the
    # 4-hour window after an engine-changing release, from the engine's Strict start). PIM_Telemetry_ReleaseControl: ON by
    # default on every ring since Invardia confirmed the fields (2026-10-16); 0/off/false/no = off. Identified only.
    $rcOn = $false; $rcFields = $null
    if ($on -and "$key".Trim()) {
        if (-not (Get-Command Test-PimReleaseControlFieldsOn -ErrorAction SilentlyContinue)) { $rcLib = Join-Path $PSScriptRoot 'PIM-ReleaseControl.ps1'; if (Test-Path -LiteralPath $rcLib) { . $rcLib } }
        if (Get-Command Test-PimReleaseControlFieldsOn -ErrorAction SilentlyContinue) {
            $rcOn = [bool](Test-PimReleaseControlFieldsOn -Value "$env:PIM_Telemetry_ReleaseControl")
            if ($rcOn) {
                $rcWave = $null; try { $rcWave = & $get 'ReleaseWave' } catch { $rcWave = $null }
                $rcStrict = $null; try { if (Get-Command Get-PimGuardStrictState -ErrorAction SilentlyContinue) { $rcStrict = Get-PimGuardStrictState } } catch { $rcStrict = $null }
                try { $rcFields = Get-PimReleaseControlHeartbeatFields -WaveRecord $rcWave -StrictState $rcStrict -NowUtc $NowUtc } catch { $rcFields = $null }
            }
        }
    }
    # §33.0 MORE TELEMETRY: the structured fields -- each ON unless its own PIM_UPLINK_<FIELD> switch is 0/false/off/no; identified only.
    # A PLAIN scriptblock (dynamic scope; every name it reads starts with sfJob so nothing in the cycle can shadow it),
    # invoked by the cycle ONLY when the identified heartbeat is due.
    $stateSb = $null
    $sfJobSw = Get-PimUplinkStateFieldSwitches
    if ($on -and "$key".Trim() -and @($sfJobSw.Values | Where-Object { $_ }).Count) {
        $sfJobCs = $cs; $sfJobGet = $get; $sfJobUs = $us; $sfJobUsRead = [bool]$usRead; $sfJobNow = $NowUtc
        $sfJobRuns = $null; if ($runsRead) { $sfJobRuns = [object[]]@($runs) }
        $stateSb = {
            $sfQ = $null; if (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue) { $sfQ = { param($sql) @(Invoke-PimSqlQuery -ConnectionString $sfJobCs -Sql $sql) } }
            $sfSched = $null; $sfProd = $null; $sfStateJobs = @()
            if ($sfJobSw['Jobs']) {
                try { if (Get-Command Get-PimJobSchedule -ErrorAction SilentlyContinue) { $sfSched = [object[]]@(Get-PimJobSchedule) } } catch { $sfSched = $null }
                try { if (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) { $sfProd = [string[]]@(Get-PimDefaultJobSchedule | ForEach-Object { "$($_.name)" }) } } catch { $sfProd = $null }
                try { if (Get-Command Get-PimSchedulerState -ErrorAction SilentlyContinue) { $sfSs = Get-PimSchedulerState; if ($sfSs -and $sfSs.jobs) { $sfStateJobs = [object[]]@($sfSs.jobs) } } } catch { $sfStateJobs = @() }
            }
            $sfGates = $null; $sfCat = $null
            if ($sfJobSw['FeaturesChanged'] -and (Get-Command Get-PimFeatureGateState -ErrorAction SilentlyContinue)) { try { $sfGates = (Get-PimFeatureGateState).gates; $sfCat = [object[]]@(Get-PimFeatureCatalog) } catch { $sfGates = $null; $sfCat = $null } }
            $sfHyOn = $false; try { if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) { $sfHyOn = [bool](Test-PimFeatureAvailable -Key 'hybrid.ad' -Quiet) } } catch { $sfHyOn = $false }
            $sfHw = $null; if ($sfHyOn -and (Get-Command Get-PimHybridWorkerJobStatus -ErrorAction SilentlyContinue)) { try { $sfHw = Get-PimHybridWorkerJobStatus -Type 'hybrid-ad-sync' -NowUtc $sfJobNow } catch { $sfHw = $null } }
            Get-PimUplinkStateFields -Switches $sfJobSw -GetSetting $sfJobGet -Query $sfQ -Runs $sfJobRuns -Schedule $sfSched -ProductJobNames $sfProd -StateJobs $sfStateJobs `
                -UpdateState $sfJobUs -UpdateStateRead $sfJobUsRead -Gates $sfGates -Catalog $sfCat -HybridAdOn $sfHyOn -HybridWorkerState $sfHw -NowUtc $sfJobNow
        }
    }
    $r = Invoke-PimUplinkCycle -GetSetting $get -SetSetting $set -Send $send -Enabled $on -InstallKey $key -Version $ver -Ring $ring `
            -Runs $runs -License $lic -ProHere $proHere -TenantId $tid -RuntimeIdentity $rid -NowUtc $NowUtc -PauseMs $pause @cyc `
            -SetupEnabled $setupOn -SetupFacts $facts -SetupExtended (Test-PimUplinkSetupExtended) -SqlSpace $sqlSpace -AssetCounts $assets -Endpoints $endpoints -AdoptionCounts $adoption `
            -ScenarioRole $scRole -ManagingTenantId $mgTid -EngineFailures $engFails -UpdateRun $updRun -Causes $causesOn -LicenceProbe $licProbe -HybridAd $hyAd `
            -ReleaseControl $rcOn -ReleaseControlFields $rcFields -StateFields $stateSb
    # PIM 100.75: a failed send / an install that should be identified but is anonymous = a WARNING run (never a failure).
    $rawKey = ''; try { $rawKey = "$(& $get 'InvardiaInstallKey')".Trim() } catch { $rawKey = '' }
    $claimSt = $null; try { $claimSt = & $get 'InstallKeyClaimState'; if ($claimSt -is [string]) { $claimSt = $claimSt | ConvertFrom-Json } } catch { $claimSt = $null }
    $licReg = [bool]$proHere
    if (-not $licReg -and $lic) { try { $licReg = [bool]("$($lic.Status)" -in @('Valid', 'Grace')) } catch { } }
    $w = Get-PimUplinkDeliveryWarning -Enabled $on -Cycle $r -StoredKeyRaw $rawKey -ResolvedKey "$key" -LicenceRegistered $licReg -ClaimState $claimSt
    $detail = "uplink: $($r.message)"
    if ($w.warning) { $detail += " -- WARNING: $($w.reason)" }
    [pscustomobject]@{ ran = [bool]$r.ran; whatIf = [bool]$WhatIf; detail = $detail
                       warning = [bool]$w.warning; warningKind = "$($w.kind)"; warningSummary = "$($w.summary)" }
}
