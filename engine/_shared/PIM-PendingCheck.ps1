<#
  PIM-PendingCheck.ps1 -- §79.2 THE DAILY UNCOMMITTED-CHANGE CHECK (operator 2026-09-25): "make daily check to see if
  missing commits exist. Make option ins settings to define if enabled and cadence (super admin only)".

  Scheduler job 'pending-check' (daily, on by default; on/off + cadence on the Jobs page, whose schedule is SuperAdmin-
  only). It finds work that was STARTED and never finished:
    * staged changes in the SHARED pending store (§79.13, pim.Settings['PendingChanges']) older than -MinAgeHours
      (default 24) -- per record type, who staged how many, the oldest;
    * queued directory actions (pim.ChangeQueue, Status 'pending': TAP re-issue, revoke, ...) never committed, same age.
  Committed-but-not-applied is NOT repeated here: 'verify-convergence' (every 30 min) already fails loudly on it.
  Mails under the Alerting event 'pending-uncommitted' (on/off), linking Pending changes. Reports only.
#>

Set-StrictMode -Off
$script:PimPendingCheckAlertEvent = 'pending-uncommitted'

function Get-PimPendingCheckFindings {
    <#
      PURE. -Doc: the shared pending document ({ bases = @{ <entity> = @{ changes } } }); -Queue: pending ChangeQueue
      entries ({ Entity; Key; Op; By; EnqueuedUtc; Kind }). Returns [ { source = staged|queued; entity; count; by[]; oldestUtc;
      ageHours } ] for everything older than -MinAgeHours.
    #>
    param([AllowNull()][object]$Doc, [AllowNull()][AllowEmptyCollection()][object[]]$Queue = @(), [datetime]$NowUtc = [datetime]::UtcNow, [double]$MinAgeHours = 24)
    $now = $NowUtc.ToUniversalTime()
    $age = { param($iso) try { [math]::Round(($now - ([datetime]::Parse("$iso", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal'))).TotalHours, 1) } catch { -1 } }
    $out = New-Object System.Collections.Generic.List[object]
    $bases = if ($Doc -and $Doc.bases) { $Doc.bases } else { @{} }
    $names = if ($bases -is [System.Collections.IDictionary]) { @($bases.Keys) } else { @($bases.PSObject.Properties | ForEach-Object Name) }
    foreach ($b in $names) {
        $entry = if ($bases -is [System.Collections.IDictionary]) { $bases[$b] } else { $bases.$b }
        $old = @(@($entry.changes) | Where-Object { $_ -and (& $age $_.atUtc) -ge $MinAgeHours })
        if (-not $old.Count) { continue }
        $oldest = @($old | Sort-Object { "$($_.atUtc)" } | Select-Object -First 1)[0]
        $out.Add([pscustomobject]@{ source = 'staged'; entity = "$b"; count = $old.Count; by = @($old | ForEach-Object { "$($_.by)" } | Where-Object { $_ } | Sort-Object -Unique)
                                    oldestUtc = "$($oldest.atUtc)"; ageHours = (& $age $oldest.atUtc) })
    }
    $q = @(@($Queue) | Where-Object { $_ -and (& $age $_.EnqueuedUtc) -ge $MinAgeHours })
    foreach ($g in @($q | Group-Object { "$($_.Entity)" })) {
        $oldest = @($g.Group | Sort-Object { "$($_.EnqueuedUtc)" } | Select-Object -First 1)[0]
        $out.Add([pscustomobject]@{ source = 'queued'; entity = "$($g.Name)"; count = $g.Count; by = @($g.Group | ForEach-Object { "$($_.By)" } | Where-Object { $_ } | Sort-Object -Unique)
                                    oldestUtc = "$($oldest.EnqueuedUtc)"; ageHours = (& $age $oldest.EnqueuedUtc) })
    }
    return @($out.ToArray())
}

function Invoke-PimPendingCheckJob {
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [double]$MinAgeHours = 24)
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[pending-check] no SQL store -- the shared pending changes and the queue cannot be read' }
    $doc = $null
    if (Get-Command Read-PimSharedPendingStore -ErrorAction SilentlyContinue) { $doc = (Read-PimSharedPendingStore -ConnectionString $cs).doc }
    $queue = @()
    if (Get-Command Get-PimSqlQueue -ErrorAction SilentlyContinue) { try { $queue = @(Get-PimSqlQueue -ConnectionString $cs -Status 'pending') } catch { $queue = @() } }
    $f = @(Get-PimPendingCheckFindings -Doc $doc -Queue $queue -NowUtc $NowUtc -MinAgeHours $MinAgeHours)
    if ($f.Count -and -not $WhatIf -and (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) {
        $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
        $lines = @($f | ForEach-Object {
            '&bull; <b>' + (& $enc $_.entity) + '</b>: ' + $_.count + $(if ($_.source -eq 'staged') { ' staged change(s)' } else { ' queued action(s)' }) +
            ' by ' + (& $enc (@($_.by) -join ', ')) + ' -- the oldest ' + [math]::Floor([double]$_.ageHours) + ' h old' })
        $n = ($f | Measure-Object -Property count -Sum).Sum
        $detail = "$n change(s) were started and never committed (older than $MinAgeHours h). Nothing reaches the tenant until someone commits them.<br><br>" + ($lines -join '<br>')
        try { [void](Send-PimJobAlertViaNotify -Event $script:PimPendingCheckAlertEvent -Title ("{0} change(s) waiting to be committed" -f $n) -Detail $detail -LinkTab 'save' -DebounceMinutes 1380 `
                        -Headline 'Changes were staged or queued but never committed.' -Action 'Open Pending changes: commit what should go through, discard what should not.') } catch { Write-Warning "[pending-check] the alert could not be sent: $($_.Exception.Message)" }
    }
    $staged = @($f | Where-Object { $_.source -eq 'staged' } | Measure-Object -Property count -Sum).Sum
    $queued = @($f | Where-Object { $_.source -eq 'queued' } | Measure-Object -Property count -Sum).Sum
    [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf
        detail = ("pending-check: {0} staged change(s) and {1} queued action(s) older than {2} h, never committed" -f [int]$staged, [int]$queued, $MinAgeHours) }
}
