<#
  Offline tests for the ALERT FEED + recorded-send proof + expiring-access
  evaluation (engine/_shared/PIM-AlertFeed.ps1 -- REQUIREMENTS §26c / §28 [H2]
  + the [M5] residual "prove a recorded send").

  Proves:
    * New-PimAlertRecord folds a Send-PimManagerAlert result into a durable proof
      record (sendState sent/rendered/suppressed) -- the [M5]-residual proof shape;
    * the dedupe key is stable across identical alerts + whitespace/case noise;
    * Test-PimAlertDebounced suppresses an identical alert inside the window only;
    * Add-PimAlertToFeed prepends newest-first + clamps to MaxKeep;
    * Select-PimAlertFeed filters by event / sentOnly / since + pages;
    * Get-PimAlertFeedSummary rolls up total / sent / unsent / per-event for Home;
    * Get-PimExpiringAccessAlert fires only on rows expiring inside the window;
    * the JSONL file adapter round-trips (UTF8 no-BOM) + retention clamps.

  PURE -- no network, clock injected, feed file in a temp dir.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-AlertFeed.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
$now = ([datetime]'2026-06-16T12:00:00Z').ToUniversalTime()

Write-Host "=== PIM-AlertFeed tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. New-PimAlertRecord -- the recorded-send PROOF ([M5] residual)
# ---------------------------------------------------------------------------
$sentResult = @{ event = 'break-glass'; fired = $true; sent = 2; recipients = @('a@x.io','b@x.io'); reason = '' }
$recSent = New-PimAlertRecord -Event 'break-glass' -Title 'Break-glass ACTIVATED' -Detail 'by ops; reason X' -LinkTab 'governance' -SendResult $sentResult -NowUtc $now
Assert 'record: event carried'            ($recSent.event -eq 'break-glass')
Assert 'record: sendState=sent on delivery' ($recSent.sendState -eq 'sent')
Assert 'record: sent count = 2'           ([int]$recSent.sent -eq 2)
Assert 'record: recipients recorded (the proof)' (@($recSent.recipients).Count -eq 2 -and $recSent.recipients -contains 'a@x.io')
Assert 'record: has id + ISO ts'          ("$($recSent.id)".Length -gt 0 -and "$($recSent.ts)" -match '^\d{4}-\d\d-\d\dT')

$renderedResult = @{ event = 'drift'; fired = $true; sent = 0; recipients = @('a@x.io'); reason = 'no sender' }
$recRender = New-PimAlertRecord -Event 'drift' -Title 'Drift' -Detail 'm=1' -SendResult $renderedResult -NowUtc $now
Assert 'record: fired-but-not-sent -> rendered' ($recRender.sendState -eq 'rendered')

$suppResult = @{ event = 'drift'; fired = $false; sent = 0; recipients = @(); reason = 'no recipients configured' }
$recSupp = New-PimAlertRecord -Event 'drift' -Title 'Drift' -Detail 'm=1' -SendResult $suppResult -NowUtc $now
Assert 'record: never-fired -> suppressed' ($recSupp.sendState -eq 'suppressed')

# ---------------------------------------------------------------------------
# 2. Dedupe key -- stable across whitespace/case noise, distinct per condition
# ---------------------------------------------------------------------------
$k1 = Get-PimAlertDedupeKey -Event 'drift' -Title 'Configuration drift' -Detail 'missing=1 changed=0 extra=2'
$k2 = Get-PimAlertDedupeKey -Event 'DRIFT' -Title '  configuration   DRIFT ' -Detail 'MISSING=1 changed=0 extra=2'
Assert 'dedupe: identical condition hashes same (case/space)' ($k1 -eq $k2)
$k3 = Get-PimAlertDedupeKey -Event 'drift' -Title 'Configuration drift' -Detail 'missing=2 changed=0 extra=2'
Assert 'dedupe: different detail hashes different' ($k1 -ne $k3)

# ---------------------------------------------------------------------------
# 3. Debounce -- identical alert inside the window is suppressed; outside fires
# ---------------------------------------------------------------------------
$feed0 = @(
    [pscustomobject]@{ ts = $now.AddMinutes(-10).ToString('o'); event = 'drift'; title = 'Configuration drift'; detail = 'missing=1 changed=0 extra=2' }
)
$keyDup = Get-PimAlertDedupeKey -Event 'drift' -Title 'Configuration drift' -Detail 'missing=1 changed=0 extra=2'
Assert 'debounce: identical within 60m -> debounced' (Test-PimAlertDebounced -Feed $feed0 -DedupeKey $keyDup -NowUtc $now -DebounceMinutes 60)
Assert 'debounce: identical but window=5m -> not debounced' (-not (Test-PimAlertDebounced -Feed $feed0 -DedupeKey $keyDup -NowUtc $now -DebounceMinutes 5))
Assert 'debounce: DebounceMinutes 0 disables' (-not (Test-PimAlertDebounced -Feed $feed0 -DedupeKey $keyDup -NowUtc $now -DebounceMinutes 0))
$keyOther = Get-PimAlertDedupeKey -Event 'engine-failure' -Title 'Job FAILED' -Detail 'x'
Assert 'debounce: different alert not debounced' (-not (Test-PimAlertDebounced -Feed $feed0 -DedupeKey $keyOther -NowUtc $now -DebounceMinutes 60))

# ---------------------------------------------------------------------------
# 4. Add-PimAlertToFeed -- newest-first + clamp
# ---------------------------------------------------------------------------
$feed = @()
$feed = Add-PimAlertToFeed -Record ([pscustomobject]@{ id='1'; ts=$now.AddMinutes(-3).ToString('o'); event='drift' }) -Feed $feed
$feed = Add-PimAlertToFeed -Record ([pscustomobject]@{ id='2'; ts=$now.ToString('o'); event='break-glass' }) -Feed $feed
Assert 'add: newest is first'      ($feed[0].id -eq '2')
Assert 'add: count grows'          (@($feed).Count -eq 2)
$big = @(); for ($i=0; $i -lt 10; $i++) { $big = Add-PimAlertToFeed -Record ([pscustomobject]@{ id="$i"; ts=$now.AddMinutes(-$i).ToString('o'); event='drift' }) -Feed $big -MaxKeep 5 }
Assert 'add: clamped to MaxKeep'   (@($big).Count -eq 5)

# ---------------------------------------------------------------------------
# 5. Select-PimAlertFeed -- filters + paging
# ---------------------------------------------------------------------------
$mixed = @(
    [pscustomobject]@{ id='a'; ts=$now.AddMinutes(-1).ToString('o'); event='drift';         sent=0 }
    [pscustomobject]@{ id='b'; ts=$now.AddMinutes(-2).ToString('o'); event='break-glass';   sent=3 }
    [pscustomobject]@{ id='c'; ts=$now.AddMinutes(-3).ToString('o'); event='drift';         sent=2 }
    [pscustomobject]@{ id='d'; ts=$now.AddDays(-9).ToString('o');    event='engine-failure'; sent=1 }
)
Assert 'select: event filter'   (@(Select-PimAlertFeed -Feed $mixed -Event 'drift').Count -eq 2)
Assert 'select: sentOnly'       (@(Select-PimAlertFeed -Feed $mixed -SentOnly).Count -eq 3)
Assert 'select: newest first'   ((Select-PimAlertFeed -Feed $mixed)[0].id -eq 'a')
Assert 'select: take pages'     (@(Select-PimAlertFeed -Feed $mixed -Take 2).Count -eq 2)
Assert 'select: since window'   (@(Select-PimAlertFeed -Feed $mixed -SinceUtc $now.AddDays(-1)).Count -eq 3)

# ---------------------------------------------------------------------------
# 6. Get-PimAlertFeedSummary -- Home tile rollup
# ---------------------------------------------------------------------------
$sum = Get-PimAlertFeedSummary -Feed $mixed -NowUtc $now -WindowHours 168
Assert 'summary: total in window (excludes 9-day-old)' ([int]$sum.total -eq 3)
Assert 'summary: sent count (proof headline)'          ([int]$sum.sent -eq 2)
Assert 'summary: unsent count'                          ([int]$sum.unsent -eq 1)
Assert 'summary: per-event drift=2'                     ([int]$sum.byEvent['drift'] -eq 2)
Assert 'summary: latest is newest'                      ($sum.latest.event -eq 'drift')

# ---------------------------------------------------------------------------
# 7. Get-PimExpiringAccessAlert -- pure fire decision
# ---------------------------------------------------------------------------
$rows = @(
    [pscustomobject]@{ principal='alice'; role='GA';    end=$now.AddDays(3).ToString('o');  type='eligible' }  # in window
    [pscustomobject]@{ principal='bob';   role='Owner'; end=$now.AddDays(20).ToString('o'); type='active'   }  # outside (>14d)
    [pscustomobject]@{ principal='carol'; role='Reader';end=$now.AddDays(-1).ToString('o'); type='active'   }  # already past
    [pscustomobject]@{ principal='dave';  role='Helpdesk';end=''                            ; type='active'   }  # no end -> ignored
)
$ea = Get-PimExpiringAccessAlert -Rows $rows -NowUtc $now -WindowDays 14
Assert 'expiring: fires when something in window'  ($ea.fire)
Assert 'expiring: counts only the in-window row'   ([int]$ea.count -eq 1)
Assert 'expiring: detail mentions the principal'   ($ea.detail -match 'alice')
$eaNone = Get-PimExpiringAccessAlert -Rows @() -NowUtc $now -WindowDays 14
Assert 'expiring: no rows -> no fire'              (-not $eaNone.fire -and [int]$eaNone.count -eq 0)

# ---------------------------------------------------------------------------
# 8. JSONL file adapter -- round-trip + retention clamp
# ---------------------------------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pim-alertfeed-{0}" -f ([guid]::NewGuid().ToString('N')))
$feedFile = Join-Path $tmp 'pim-alerts.jsonl'
try {
    Assert 'file: read missing -> empty' (@(Read-PimAlertFeedFile -FeedFile $feedFile).Count -eq 0)
    $r1 = New-PimAlertRecord -Event 'drift' -Title 'Drift' -Detail 'm=1' -SendResult @{ fired=$true; sent=1; recipients=@('x@x.io') } -NowUtc $now
    Write-PimAlertFeedFile -FeedFile $feedFile -Record $r1
    $back = @(Read-PimAlertFeedFile -FeedFile $feedFile)
    Assert 'file: round-trips one record'    ($back.Count -eq 1 -and $back[0].event -eq 'drift')
    Assert 'file: recipients survive JSON'    (@($back[0].recipients) -contains 'x@x.io')
    # no BOM at the start of the file
    $bytes = [System.IO.File]::ReadAllBytes($feedFile)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Assert 'file: UTF8 no-BOM (PS 5.1-safe)'  (-not $hasBom)
    # retention: push past MaxKeep+50, expect clamp to MaxKeep
    for ($i=0; $i -lt 70; $i++) { Write-PimAlertFeedFile -FeedFile $feedFile -Record (New-PimAlertRecord -Event 'drift' -Title "D$i" -Detail "n=$i" -SendResult @{ fired=$true; sent=1 } -NowUtc $now.AddSeconds($i)) -MaxKeep 10 }
    Assert 'file: retention clamps near MaxKeep' (@(Read-PimAlertFeedFile -FeedFile $feedFile).Count -le 60)
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host ("RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
