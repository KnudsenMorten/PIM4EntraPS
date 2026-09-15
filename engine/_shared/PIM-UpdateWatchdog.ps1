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
        [datetime]$Now = (Get-Date).ToUniversalTime()
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

    $succeeded = @($ex | Where-Object { "$($_.status)" -eq 'Succeeded' })
    $lastOk = $null
    foreach ($s in $succeeded) {
        $t = ConvertTo-PimUtcOrNull -Value "$($s.startTime)"
        if ($t -and (-not $lastOk -or $t -gt $lastOk)) { $lastOk = $t }
    }
    if ($lastOk) {
        $age = ($Now - $lastOk).TotalHours
        if ($age -lt $StaleAfterHours) {
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
    if ($failures -lt $MinFailures) {
        return (& $none "only $failures failure(s) since the last success -- below the $MinFailures needed to act" $failures)
    }

    $since = if ($lastOk) { "no success since $($lastOk.ToString('u'))" } else { 'it has never succeeded' }
    @{ action   = 'restore'
       reason   = "$failures failure(s) and $since -- restoring the last image that completed an update"
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
        $lastGood = ''
        foreach ($c in $containers) {
            foreach ($v in @($c.env)) {
                if ("$($v.name)" -eq 'PIM_UPDATE_LAST_GOOD') { $lastGood = "$($v.value)".Trim() }
            }
        }
        $execs = @(Invoke-PimArm -Method GET -Path "$base/executions" -ApiVersion $script:PimAcaApi -All) |
                 ForEach-Object {
                     [pscustomobject]@{ name = "$($_.name)"
                                        status = "$($_.properties.status)"
                                        startTime = "$($_.properties.startTime)" }
                 }
        $plan = Get-PimUpdateWatchdogPlan -Executions $execs -CurrentImage $current -LastGoodImage $lastGood `
                    -StaleAfterHours $StaleAfterHours -MinFailures $MinFailures
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
