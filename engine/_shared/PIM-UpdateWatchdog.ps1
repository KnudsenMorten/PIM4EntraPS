#Requires -Version 5.1
<#
.SYNOPSIS
    Restore the nightly updater when it has adopted a build it cannot run. §56.5.

.DESCRIPTION
    🔴 THE ONE FAILURE THE UPDATER CANNOT RECOVER FROM ITSELF.
    `ca-pim-update` stamps ITSELF last, and only after the Manager has rolled onto that same image
    and passed a health check -- so the Manager is a canary. But the Manager and the updater are
    DIFFERENT ENTRY POINTS IN THE SAME IMAGE. Measured 2026-09-10: 2.4.296-2.4.301 carried a broken
    `update-job-entry.ps1` (wrong solution-root depth) while the Manager booted perfectly. That
    image would have passed the canary and been adopted.

    An adopted-but-broken updater then fails every night forever, and **cannot repair itself: the
    thing that would fix it is the broken thing.** Recovery means a human inside the tenant, which
    is exactly what this whole design exists to remove. At three environments that is an afternoon;
    at a hundred it is the failure that defines the product.

    🔑 SO THE REPAIR COMES FROM OUTSIDE THE JOB. The tick job runs every five minutes, carries the
    same image, and is health-gated by the same roll -- so it can see that the update job has not
    succeeded in a long time and put it back on the last image that DID complete a full update.

    The decision is a pure function because it rewrites the updater's image with nobody watching.

.NOTES
    PS 5.1-safe. Get-PimUpdateWatchdogPlan touches nothing; Invoke-PimUpdateWatchdog does the ARM
    read and the single write.
#>

function ConvertTo-PimUtcOrNull {
    <#
      A timestamp string as UTC, or $null when it is absent or unparseable.
      🪤 NOT [datetime]::TryParse with a [ref] to an unassigned variable: PS 5.1 cannot resolve the
      overload against $null and throws "Cannot find an overload for TryParse and the argument
      count: 2" -- at parse time this looks perfectly reasonable, and it fails on the first call.
    #>
    param([string]$Value)
    if (-not "$Value".Trim()) { return $null }
    # 🪤 NOT [datetime]"$Value" -- a CAST reads the AMBIENT CULTURE, so on a de-DE host '2026-03-04'
    # parses as 3 April instead of 4 March. This function decides how long the updater has been
    # failing, so a month-shifted stamp either restores a healthy environment or leaves a broken one
    # broken. Invariant first (which is what ToString('o') writes), then the operator's own culture.
    if (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) { return (Get-PimUtcStamp $Value) }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::CurrentCulture,  $styles, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function Get-PimUpdateWatchdogQuickUpdateSeconds {
    <# LITERAL. 3.1.73 review round 2 X2 (b): a quick-slot execution that ran at least this long STARTED an update (a quick
       check alone ends in seconds; an update rolls apps / jobs for minutes). #>
    return 240
}

function ConvertTo-PimUpdateWatchdogImageRef {
    <# PURE. 3.1.73 round 6 V3: an image reference as @{ repo; tag; digest } -- '<registry>/<repo>:<tag>', '<registry>/<repo>@sha256:<64>'
       or '<registry>/<repo>:<tag>@sha256:<64>' (the forms the updater / setup write: Set-PimAcaJobImage takes the tag, a
       re-point by digest the @sha256 form). The registry host is lower-cased (DNS), the repo kept; a tag is the part after the
       LAST ':' that follows the last '/' (a registry port is not a tag). Unreadable = $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Ref)
    $s = "$Ref".Trim(); if (-not $s) { return $null }
    $dg = ''; $at = $s.IndexOf('@'); if ($at -ge 0) { $dg = $s.Substring($at + 1).ToLowerInvariant(); $s = $s.Substring(0, $at) }
    if ($dg -and $dg -notmatch '^sha256:[0-9a-f]{64}$') { return $null }
    $tag = ''; $sl = $s.LastIndexOf('/'); $co = $s.LastIndexOf(':')
    if ($co -gt $sl) { $tag = $s.Substring($co + 1); $s = $s.Substring(0, $co) }
    $fs = $s.IndexOf('/'); $repo = $(if ($fs -gt 0) { $s.Substring(0, $fs).ToLowerInvariant() + $s.Substring($fs) } else { $s })
    if (-not $repo) { return $null }
    return @{ repo = $repo; tag = $tag; digest = $dg }
}

function Test-PimUpdateWatchdogSameImage {
    <# PURE. 3.1.73 round 6 V3: is -A the same image as -B? The SAME digest (both carry one), else the same repository AND tag (both
       carry one). A tag on one side and only a digest on the other cannot be told apart here = $false (the caller keeps its fall-back,
       lastModifiedAt). ⛔ SUPERSEDED (round 5 P6): exact text. #>
    param([AllowNull()][AllowEmptyString()][string]$A, [AllowNull()][AllowEmptyString()][string]$B)
    $x = ConvertTo-PimUpdateWatchdogImageRef -Ref $A; $y = ConvertTo-PimUpdateWatchdogImageRef -Ref $B
    if (-not $x -or -not $y) { return $false }
    if ($x.digest -and $y.digest) { return [bool]($x.digest -eq $y.digest) }
    if ($x.repo -ne $y.repo) { return $false }
    return [bool]($x.tag -and $y.tag -and $x.tag -eq $y.tag)
}

function Get-PimUpdateWatchdogCrashStreak {
    <# LITERAL. 3.1.73 review round 3 Y2: this many CONSECUTIVE failed quick slots (two hours of 15-minute slots) = one failure. #>
    return 8
}

function Get-PimUpdateWatchdogCodeDayGapHours {
    <# PURE. 3.1.73 review round 2 X2 (a): the LONGEST gap, in hours, between two consecutive code days of -NightlyDays
       (PIM_UPDATE_NIGHTLY_DAYS) over the last 400 days before -Now: daily = 24, weekly = 168, monthly '1 * *' = up to 744.
       '' / '* * *' = 24. $null = no code day at all in that window (an unreadable pattern; Test-PimUpdateNowDayMatch). #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyDays, [datetime]$Now = (Get-Date).ToUniversalTime())
    if (-not "$NightlyDays".Trim()) { return 24 }
    if (-not (Get-Command Test-PimUpdateNowDayMatch -ErrorAction SilentlyContinue)) { return $null }
    $d0 = $Now.ToUniversalTime().Date
    $prev = $null; $max = 0
    for ($i = 400; $i -ge 0; $i--) {
        $d = [datetime]::SpecifyKind($d0.AddDays(-$i), [DateTimeKind]::Utc)
        if (-not (Test-PimUpdateNowDayMatch -Days "$NightlyDays" -DateUtc $d)) { continue }
        if ($null -ne $prev) { $g = ($d - $prev).TotalHours; if ($g -gt $max) { $max = $g } }
        $prev = $d
    }
    if ($null -eq $prev) { return $null }
    if ($max -le 0) { return 9600 }   # one code day in 400 days: the gap is at least the window
    return $max
}

function Get-PimUpdateWatchdogPlan {
    <#
      PURE. Decide whether the update job should be put back on its last-known-good image.
      Returns @{ action = 'none'|'restore'; reason; toImage; failures }.

      -Executions: objects with .name, .status ('Succeeded'|'Failed'|'Running'|...) and .startTime.
      -CurrentImage / -LastGoodImage: what the job runs now, and the last image that completed a
       full update successfully.
      -StaleAfterHours: how long without a success before the updater is considered stuck.
      -MinFailures: how many failures must have happened. A SINGLE failure is not enough -- one
       transient failure was measured the same day this was written, and its immediate re-run was
       clean. Rolling the updater back on one bad night would be its own outage.
    #>
    param(
        [object[]]$Executions = @(),
        [string]$CurrentImage,
        [string]$LastGoodImage,
        [double]$StaleAfterHours = 48,
        [int]$MinFailures = 2,
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        # 2.4.646 (framework 8.18 UPDATE-NOW): the updater job's PIM_UPDATE_NIGHTLY_UTC and whether update now is ON. With
        # both, the job runs every 15 minutes and most executions are seconds-long signal checks that always exit 0 -- they
        # must never count as "the updater works", or a nightly that fails every night stays hidden behind them.
        [AllowEmptyString()][string]$NightlyUtc = '',
        # FIXED 2026-11-27 (3.1.72 final review F1, for 3.1.73): IGNORED for the classification -- since SEC-PATCH-PIPELINE-1
        # pt 9 the quarter-hour slots carry the security check WHATEVER PIM_UPDATE_NOW says, so a quick success never proves the
        # full-update path, update now on or off. Kept for callers. ⛔ SUPERSEDED: "quick successes are left out only when on".
        [bool]$UpdateNowOn = $false,
        # F1: the job's PIM_UPDATE_NIGHTLY_DAYS ('' = every day): on a weekly / monthly install the nightly TIME of an off day is
        # a quick (security-only) slot too (Get-PimUpdaterRunKind -NightlyDays), so its success proves nothing either.
        [AllowNull()][AllowEmptyString()][string]$NightlyDays = '',
        # Z1 (3.1.73 round 4): when the job's current image was stamped (systemData.lastModifiedAt); $null = not known
        [AllowNull()][object]$ImageSinceUtc = $null
    )
    # 🪤 CARRY THE COUNT EVEN WHEN NOT ACTING. The first version hard-coded failures = 0 on every
    # no-action path, so "1 failure, below the threshold" reported ZERO failures -- the caller could
    # not distinguish "nothing wrong" from "something is wrong but not yet enough to act on", which
    # is exactly the state an operator wants to see building up.
    $none = { param($r, $f = 0) @{ action = 'none'; reason = $r; toImage = ''; failures = $f } }

    # 🔒 NOTHING TO GO BACK TO IS NOT A REASON TO ACT. Without a recorded known-good image there is
    # no safe target, and guessing one (the newest tag, say) could put the updater on something
    # that has never run here at all.
    $good = "$LastGoodImage".Trim()
    if (-not $good) { return (& $none 'no last-known-good image recorded -- nothing to restore to') }
    if ($good -eq "$CurrentImage".Trim()) {
        # Already restored, or never moved. Self-limiting: once the repair lands, this is the
        # branch every subsequent tick takes, so it repairs once rather than every five minutes.
        return (& $none 'already on the last-known-good image')
    }

    $ex = @($Executions | Where-Object { $_ -and "$($_.status)".Trim() })
    # 🪤 A JOB THAT HAS NEVER RUN IS NOT A BROKEN JOB. A freshly-armed updater has no history until
    # its first cron fires; "no successes" is trivially true for it, and restoring it would undo an
    # install nobody has even tried yet.
    if (-not $ex.Count) { return (& $none 'the update job has no execution history yet') }

    # 2.4.646: ONLY A FULL UPDATE RUN PROVES THE UPDATER WORKS. With update now on, an execution that starts on a 15-minute
    # slot (not the nightly one, the first of its slot) is a quick signal check (Get-PimUpdaterRunKind, the rule the updater
    # applies to itself): a Succeeded one says nothing about the update and is left out of the successes. A FAILED one stays a
    # failure -- a check never fails on its own, so it was a full update the signal started there.
    # F1 (3.1.73): classified whatever PIM_UPDATE_NOW says (was: `-and $UpdateNowOn`), with the job's day pattern.
    # FIXED 2026-11-27 (3.1.73 review round 2 X2 (b)): a FAILED quick slot counts only when it STARTED an update there (an
    # image-only apply / an update-now run). ARM carries no outcome per execution -- only status, startTime, endTime -- so the
    # run LENGTH tells it: a quick check that only checks ends in well under Get-PimUpdateWatchdogQuickUpdateSeconds; one that
    # started an update runs for minutes. A failed quick slot with no readable end is NOT counted (fail safe: never restore a
    # healthy updater on a doubt). Nightly / manual executions count as before.
    # ⛔ SUPERSEDED (3.1.73 round 2): "A FAILED one stays a failure -- a check never fails on its own".
    $classified = $false
    $ex0 = @($ex)   # Y2 (3.1.73 round 3): every execution, for the crash-at-start streak below
    if ("$NightlyUtc".Trim() -and (Get-Command Get-PimUpdaterRunKind -ErrorAction SilentlyContinue)) {
        $classified = $true
        $longSec = Get-PimUpdateWatchdogQuickUpdateSeconds
        $exu = @($ex | ForEach-Object { [pscustomobject]@{ name = "$($_.name)"; status = "$($_.status)"; startUtc = (ConvertTo-PimUtcOrNull -Value "$($_.startTime)") } })
        $ex = @($ex | Where-Object {
            $st = ConvertTo-PimUtcOrNull -Value "$($_.startTime)"
            if (-not $st) { return ("$($_.status)" -ne 'Succeeded') }
            $k = Get-PimUpdaterRunKind -NightlyUtc "$NightlyUtc" -StartUtc $st -Executions $exu -OwnExecution "$($_.name)" -Enabled $true -NightlyDays "$NightlyDays"
            if ("$($k.kind)" -ne 'quick') { return $true }
            if ("$($_.status)" -ne 'Failed') { return $false }
            $en = $(if ($_.PSObject.Properties['endTime']) { ConvertTo-PimUtcOrNull -Value "$($_.endTime)" } else { $null })
            return [bool]($en -and ($en - $st).TotalSeconds -ge $longSec)
        })
        if (-not $ex.Count) { return (& $none 'only 15-minute checks so far -- no full update run to judge yet') }
    }
    # X2 (a): the stale window follows the install's CODE-day interval -- a weekly / monthly install's last full run is up to a
    # period old by design: stale = the longest gap between its code days + 48 h (daily = -StaleAfterHours, 48 h, as before).
    $staleH = $StaleAfterHours
    if ($classified -and "$NightlyDays".Trim()) {
        $gap = Get-PimUpdateWatchdogCodeDayGapHours -NightlyDays "$NightlyDays" -Now $Now
        if ($null -eq $gap) { return (& $none "the code day pattern '$("$NightlyDays".Trim())' cannot be read -- this install is security-only; not judged (fix by hand)") }
        if ($gap -gt 24) { $staleH = [Math]::Max($StaleAfterHours, $gap + 48) }
    }
    $succeeded = @($ex | Where-Object { "$($_.status)" -eq 'Succeeded' })
    $lastOk = $null; $lastOkExec = $null
    foreach ($s in $succeeded) {
        $t = ConvertTo-PimUtcOrNull -Value "$($s.startTime)"
        if ($t -and (-not $lastOk -or $t -gt $lastOk)) { $lastOk = $t; $lastOkExec = $s }
    }
    # FIXED 2026-11-27 (3.1.73 review round 3 Y2): an updater that CRASHES AT START fails every quick slot in seconds -- none of
    # those counts on its own (X2 b), so on a weekly install it went unnoticed for about two weeks. A STREAK of
    # Get-PimUpdateWatchdogCrashStreak (8) or more CONSECUTIVE failed quick slots after the last success (a working quick check
    # exits 0; any Succeeded execution ends the streak) is the updater failing: every full block of 8 counts as ONE failure, and
    # such a streak voids the "healthy" window (the last full run no longer proves the updater starts).
    # FIXED 2026-11-27 (3.1.73 review round 4 Z1): an outage OUTSIDE the updater (Entra / ARM / SQL / registry pull) fails every
    # quick slot too, at any time -- a crash at start follows an IMAGE CHANGE. So a streak counts ONLY from executions that started
    # AFTER the job's current image was stamped (-ImageSinceUtc = the job's systemData.lastModifiedAt: the updater stamps itself
    # last in a full run; setup / a restore change it too); not known = no streak (fail safe). And it replaces only staleness: a
    # last full success whose run ENDED at or after that stamp (a good full run on the current image) inside the window stays
    # healthy. ⛔ SUPERSEDED (round 3 Y2): "a streak ... voids the healthy window" (whenever it started).
    # FIXED 2026-11-27 (3.1.73 review round 5 P6, B W4): the image's stamp = the START of the FIRST execution whose template image
    # IS the job's current image (executions carry their template: .image); -ImageSinceUtc (systemData.lastModifiedAt -- it moves
    # on ANY job change, e.g. a setup re-run) only when no execution shows the image. ⛔ SUPERSEDED (round 4): lastModifiedAt always.
    $since = $null
    $curImg = "$CurrentImage".Trim()
    if ($curImg) {
        foreach ($x in $ex0) {
            if (-not $x.PSObject.Properties['image'] -or -not (Test-PimUpdateWatchdogSameImage -A "$($x.image)" -B $curImg)) { continue }
            $xs = ConvertTo-PimUtcOrNull -Value "$($x.startTime)"
            if ($xs -and (-not $since -or $xs -lt $since)) { $since = $xs }
        }
    }
    if (-not $since) { $since = ConvertTo-PimUtcOrNull -Value "$ImageSinceUtc" }
    $streakFailures = 0; $streakMax = 0
    if ($classified -and $since) {
        $counted = @{}; foreach ($c in $ex) { $counted["$($c.name)"] = $true }
        $run = 0
        $ordered = @($ex0 | ForEach-Object { [pscustomobject]@{ e = $_; t = (ConvertTo-PimUtcOrNull -Value "$($_.startTime)") } } | Where-Object { $_.t } | Sort-Object t)
        foreach ($o in $ordered) {
            if ($lastOk -and $o.t -le $lastOk) { continue }
            if ($o.t -lt $since) { continue }   # Z1: only from the current image's stamp on (P6: its first execution counts)
            $stt = "$($o.e.status)"
            if ($stt -eq 'Succeeded') { $streakFailures += [Math]::Floor($run / (Get-PimUpdateWatchdogCrashStreak)); $run = 0; continue }
            if ($stt -eq 'Failed' -and -not $counted.ContainsKey("$($o.e.name)")) { $run++; if ($run -gt $streakMax) { $streakMax = $run } }
        }
        $streakFailures += [Math]::Floor($run / (Get-PimUpdateWatchdogCrashStreak))
    }
    if ($lastOk) {
        $age = ($Now - $lastOk).TotalHours
        # Z1: the streak overrides the window only when the last good full run is OLDER than the current image (its run ended
        # before the stamp); an unreadable end = the good run counts (stay healthy)
        # FIXED 2026-11-27 (3.1.73 review round 5 P5, A E3): the good run counts for the current image only when it STARTED on
        # it (its start at or after the stamp) -- ⛔ SUPERSEDED (round 4): "its run ENDED at or after the stamp" (the run that
        # rolled the image ended after its own stamp, so a crash of the NEW image was never seen).
        $goodOnCurrent = (-not $since) -or ($lastOk -ge $since)
        if ($age -lt $staleH -and ($streakFailures -lt 1 -or $goodOnCurrent)) {
            return (& $none ("last success was {0:N1}h ago -- healthy" -f $age))
        }
    }

    # Count failures SINCE the last success (or all of them, when there has never been one).
    $failures = 0
    foreach ($e in $ex) {
        if ("$($e.status)" -ne 'Failed') { continue }
        if ($lastOk) {
            $t = ConvertTo-PimUtcOrNull -Value "$($e.startTime)"
            if ($t -and $t -le $lastOk) { continue }
        }
        $failures++
    }
    # Y2 (3.1.73 round 3): each full block of 8 consecutive fast-failing quick slots = one failure
    $failures += [int]$streakFailures
    if ($failures -lt $MinFailures) {
        return (& $none "only $failures failure(s) since the last success -- below the $MinFailures needed to act" $failures)
    }

    $since = if ($lastOk) { "no success since $($lastOk.ToString('u'))" } else { 'it has never succeeded' }
    @{ action   = 'restore'
       reason   = "$failures failure(s)$(if ($streakFailures) { " ($streakFailures from $streakMax consecutive failed 15-minute checks: the updater fails at start)" }) and $since -- restoring the last image that completed an update"
       toImage  = $good
       failures = $failures }
}

function Invoke-PimUpdateWatchdog {
    <#
      Read the update job's recent executions, decide, and -- only when the decision says so --
      put it back on its last-known-good image. Returns the plan, with .acted.

      🔒 NEVER THROWS AT THE CALLER. This runs inside the five-minute tick, whose real job is engine
      reconciliation. A watchdog that can break the thing it rides on is worse than no watchdog.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string]$JobName = 'ca-pim-update',
        [double]$StaleAfterHours = 48,
        [int]$MinFailures = 2,
        [scriptblock]$Log
    )
    $say = { param($m, $c) if ($Log) { & $Log $m $c } }
    $plan = @{ action = 'none'; reason = 'not evaluated'; toImage = ''; failures = 0 }
    try {
        $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
        $job = Invoke-PimArm -Method GET -Path $base -ApiVersion $script:PimAcaApi
        if (-not $job) {
            # No updater in this environment is a normal, supported state (§55: the source is
            # optional, and so is the job). Silence would be wrong; alarm would be worse.
            & $say "  [watchdog] no '$JobName' in $ResourceGroup -- nothing to watch" 'DarkGray'
            return @{ action = 'none'; reason = 'no update job'; toImage = ''; failures = 0; acted = $false }
        }
        $containers = @($job.properties.template.containers)
        $current = if ($containers.Count -eq 1) { "$($containers[0].image)" } else { '' }
        $lastGood = ''; $nightly = ''; $unValue = ''; $unRing = ''; $nightlyDays = ''
        foreach ($c in $containers) {
            foreach ($v in @($c.env)) {
                if ("$($v.name)" -eq 'PIM_UPDATE_LAST_GOOD') { $lastGood = "$($v.value)".Trim() }
                if ("$($v.name)" -eq 'PIM_UPDATE_NIGHTLY_UTC') { $nightly = "$($v.value)".Trim() }
                if ("$($v.name)" -eq 'PIM_UPDATE_NIGHTLY_DAYS') { $nightlyDays = "$($v.value)".Trim() }   # F1 (3.1.73)
                if ("$($v.name)" -eq 'PIM_UPDATE_NOW') { $unValue = "$($v.value)".Trim() }
                if ("$($v.name)" -eq 'PIM_UPDATE_RING') { $unRing = "$($v.value)".Trim() }
            }
        }
        # 2.4.646: the job's own update-now setting, read the way the updater reads it (Test-PimUpdateNowEnabled)
        $unOn = $false
        if (Get-Command Test-PimUpdateNowEnabled -ErrorAction SilentlyContinue) { $unOn = [bool](Test-PimUpdateNowEnabled -Ring $unRing -Value $unValue) }
        $execs = @(Invoke-PimArm -Method GET -Path "$base/executions" -ApiVersion $script:PimAcaApi -All) |
                 ForEach-Object {
                     [pscustomobject]@{ name = "$($_.name)"
                                        status = "$($_.properties.status)"
                                        startTime = "$($_.properties.startTime)"
                                        endTime = "$($_.properties.endTime)"     # X2 (b) 3.1.73: the run length of a failed quick slot
                                        image = "$(@($_.properties.template.containers | Where-Object { $_ })[0].image)" }   # P6 (3.1.73 round 5): the image it ran
                 }
        $plan = Get-PimUpdateWatchdogPlan -Executions $execs -CurrentImage $current -LastGoodImage $lastGood `
                    -StaleAfterHours $StaleAfterHours -MinFailures $MinFailures -NightlyUtc $nightly -UpdateNowOn $unOn -NightlyDays $nightlyDays `
                    -ImageSinceUtc "$($job.systemData.lastModifiedAt)"   # Z1 (3.1.73 round 4): the current image's stamp time
        if ($plan.action -ne 'restore') {
            & $say "  [watchdog] $($plan.reason)" 'DarkGray'
            return ($plan + @{ acted = $false })
        }
        # 🔴 LOUD. This is an automated rollback of the component that performs updates; it must be
        # obvious in a log somebody reads later, not a quiet correction.
        & $say "  [watchdog] THE UPDATER IS STUCK: $($plan.reason)" 'Red'
        & $say "  [watchdog] restoring $JobName -> $($plan.toImage)" 'Yellow'
        [void](Set-PimAcaJobImage -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
                 -Name $JobName -Image $plan.toImage)
        & $say "  [watchdog] restored. The next scheduled run uses the last image that completed an update." 'Yellow'
        return ($plan + @{ acted = $true })
    } catch {
        & $say "  [watchdog] check skipped: $($_.Exception.Message)" 'Yellow'
        return ($plan + @{ acted = $false })
    }
}
