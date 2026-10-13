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
    if ($st -in @('running', 'skipped', 'unimplemented', 'outofscope', 'disabled', '')) { return '' }
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
        if (-not $newest -or $fin -gt $newest) { $newest = $fin }
        if (-not $byJob.Contains($job)) { $byJob[$job] = @{ job = $job; latest = $r; latestFin = $fin; failed = $null; held = $false; throttled = $null; count = 0 } }
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
        $cls = ''
        if ($outcome -eq 'warning' -and $e.throttled) { $cls = 'THROTTLED'; $txt = "$($e.throttled.detail)" }
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
function Get-PimUplinkAdoptionCountKeys {
    <# PURE. Every adoption key, in the order the heartbeat builds them (a literal: child-scope safe). #>
    return @('managedAdmins', 'managedGroups', 'delegations', 'privilegedRoles', 'eligibleAssignments', 'activeAssignments',
             'azureRoleAssignments', 'activations30d', 'approvals30d', 'accessReviewsCompleted30d', 'managedTenants',
             'hybridAdGroups', 'hybridServers')
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
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [switch]$MspMaster, [switch]$HybridAd)
    $out = @{}
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
    if ("$($r.Status)" -ne 'ok' -and "$($box.err)".Trim()) {
        $detail = "$($box.err)".Trim()
        try { $ej = $detail | ConvertFrom-Json -ErrorAction Stop; if ($ej.fields) { $detail = "fields: $(@($ej.fields) -join ', ')" } } catch { }
        if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 300) }
        $reason = "$reason [$detail]"
    }
    $o = [ordered]@{ Status = "$($r.Status)"; Reason = $reason; Sent = [bool]$r.Sent; Body = $null }
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
          [double]$HeartbeatHours = (Get-PimUplinkHeartbeatHours))
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
    $addState = @{ on = ([bool]$Additive -and -not $addHeld); refusedNow = $false; reason = '' }
    $postAdd = {
        param($rec, $names, $legacy)
        $r1 = & $post $rec
        $nm = @(@($names) | Where-Object { "$_".Trim() })
        if ("$($r1.Status)" -eq 'ok' -or $null -eq $rec -or -not $nm.Count -or -not (Test-PimUplinkValidationRefusal "$($r1.Reason)")) { return $r1 }
        foreach ($n in $nm) {
            if ($legacy -and $legacy.ContainsKey("$n")) { $rec | Add-Member -NotePropertyName "$n" -NotePropertyValue $legacy["$n"] -Force }
            else { $rec.PSObject.Properties.Remove("$n") }
        }
        $r2 = & $post $rec
        if ("$($r2.Status)" -eq 'ok') { $addState.on = $false; $addState.refusedNow = $true; $addState.reason = "$($r1.Reason)" }
        return $r2
    }
    $isId = ($sender.Mode -eq 'identified')
    $redact = { param($t, $max) $x = "$t".Trim(); if (Get-Command ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $x = ConvertTo-AitUplinkRedacted -Text $x }; if ($x.Length -gt $max) { $x = $x.Substring(0, $max - 3) + '...' }; $x }
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
        }
        $r = & $postAdd $hb $hbAdd @{}
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
        $cls = if ($p.outcome -eq 'failed') { Get-PimUplinkErrorClass -Text $p.errorText } elseif ($p.ContainsKey('errorClass') -and "$($p.errorClass)") { "$($p.errorClass)" } else { '' }
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
        $r = & $postAdd $rec $addNames $addLegacy
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
    if ($addState.refusedNow) { $msg += '; Invardia refused the new report fields -- sent in the old form, tried again in 24 h' }
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
    & $SetSetting 'UplinkState' ([pscustomobject]$newState)
    return @{ ran = $true; mode = $sender.Mode; sent = $sent; failed = $failed; left = $left; heartbeat = $hbSent; setup = $setupSent; message = $msg; reasons = @($why)
              additive = [bool]$addState.on; additiveRefused = [bool]$addState.refusedNow
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
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
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
    $us = $null; try { $us = & $get 'UpdateState'; if ($us -is [string]) { $us = $us | ConvertFrom-Json } } catch { $us = $null }
    $ring = Resolve-PimUplinkRing -EnvRing "$env:PIM_UPDATE_RING" -UpdateState $us
    $rid = if ($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT) { 'mi-container' } else { 'spn-certificate' }
    $runs = @(); if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { try { $runs = @(Get-PimJobRunHistory) } catch { $runs = @() } }
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
        $adoption = { Get-PimUplinkAdoptionCounts -Query { param($n, $s) Invoke-PimSqlScalar -ConnectionString $cs -Sql $s } -MspMaster:$adMsp -HybridAd:$adHy }
    }
    if ($on) {
        try { $ef = & $get 'EngineItemFailures'; if ($ef -is [string] -and "$ef".Trim()) { $ef = $ef | ConvertFrom-Json }; $engFails = @(@($ef) | Where-Object { $null -ne $_ }) } catch { $engFails = @() }
        $updRun = ConvertTo-PimUplinkUpdateRun -UpdateState $us
    }
    $r = Invoke-PimUplinkCycle -GetSetting $get -SetSetting $set -Send $send -Enabled $on -InstallKey $key -Version $ver -Ring $ring `
            -Runs $runs -License $lic -ProHere $proHere -TenantId $tid -RuntimeIdentity $rid -NowUtc $NowUtc -PauseMs $(if ($WhatIf) { 0 } else { 2500 }) `
            -SetupEnabled $setupOn -SetupFacts $facts -SetupExtended (Test-PimUplinkSetupExtended) -SqlSpace $sqlSpace -AssetCounts $assets -Endpoints $endpoints -AdoptionCounts $adoption `
            -ScenarioRole $scRole -ManagingTenantId $mgTid -EngineFailures $engFails -UpdateRun $updRun
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
