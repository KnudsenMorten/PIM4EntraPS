#Requires -Version 5.1
<#
.SYNOPSIS
  GUARD-1 (framework DOCS/REQUIREMENTS.md, operator 2026-10-04): every protective guard that holds, refuses or skips
  to protect data must be SEEN -- a mail to the admins, a detailed telemetry record (Invardia opens / updates a support
  ticket from it), the audit trail (guard.trip) and the Guards list on the Jobs page.

.DESCRIPTION
  Invoke-PimGuardTrip is the ONE call a guard makes when it trips. It NEVER throws (an alert must never turn the safe
  outcome into a failure) and does, each step on its own:
    1. STATE   pim.Settings 'GuardTrips': per guard id -- first / last seen, trip count, last outcome, measured values,
               the action text. The Guards list and the telemetry read it.
    2. AUDIT   action 'guard.trip' (the engine's or the Manager's audit writer, whichever is loaded).
    3. MAIL    unless the caller already mailed (-CallerMailed): one mail per guard, then at most one per -MailDedupHours
               (24) with "still tripping (N times)"; switchable with the setting GuardAlertMail ('off' = no mail).
    4. TELEMETRY  the next uplink cycle (job 'uplink', hourly) sends every guard whose last trip is newer than its last
               send as a Schema 2 Kind 'guard' record (New-PimGuardUplinkRecord) -- following the telemetry switch.
  Severity follows the outcome: halted / refused = critical, held / skipped / warning = warning (GUARD-1.3).
#>

$script:PimGuardSetting = 'GuardTrips'
$script:PimGuardOutcomes = @('halted', 'refused', 'held', 'skipped', 'warning')

function Get-PimGuardSeverity {
    param([string]$Outcome)
    if ("$Outcome".Trim().ToLowerInvariant() -in @('halted', 'refused')) { 'critical' } else { 'warning' }
}

function ConvertTo-PimGuardNumbers {
    <# PURE. Up to 10 numeric values, keys ^[a-z][A-Za-z0-9]{0,30}$ (the record's Measured / Thresholds rule). #>
    param([AllowNull()][object]$Values)
    $o = [ordered]@{}
    if (-not $Values) { return $o }
    # objects, not 2-element arrays: ONE pair in an array of arrays is unrolled by the pipeline and read letter by letter
    $pairs = if ($Values -is [System.Collections.IDictionary]) { @($Values.Keys | ForEach-Object { [pscustomobject]@{ k = "$_"; v = $Values[$_] } }) }
             else { @($Values.PSObject.Properties | ForEach-Object { [pscustomobject]@{ k = $_.Name; v = $_.Value } }) }
    foreach ($p in @($pairs | Sort-Object k)) {
        if ($o.Count -ge 10) { break }
        if ("$($p.k)" -cnotmatch '^[a-z][A-Za-z0-9]{0,30}$') { continue }
        $n = 0.0; if ([double]::TryParse("$($p.v)", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { $o["$($p.k)"] = $n }
    }
    return $o
}

function Update-PimGuardTripState {
    <#
      PURE. The new 'GuardTrips' state after one trip, and whether a mail is due.
      Returns @{ state (ordered dictionary id -> entry); entry; mailDue; sinceMail }.
    #>
    param([AllowNull()][object]$State, [Parameter(Mandatory)][string]$GuardId, [Parameter(Mandatory)][string]$Outcome,
          [string]$Area = '', [string]$Job = '', [string]$Title = '', [string]$ActionText = '', [string]$Link = '',
          [AllowNull()][object]$Measured, [AllowNull()][object]$Thresholds, [int]$HeldCount = 0,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$MailDedupHours = 24, [switch]$CallerMailed)
    $now = $NowUtc.ToUniversalTime()
    $st = [ordered]@{}
    if ($State) {
        $src = if ($State -is [string]) { try { $State | ConvertFrom-Json } catch { $null } } else { $State }
        if ($src -is [System.Collections.IDictionary]) { foreach ($k in $src.Keys) { $st["$k"] = $src[$k] } }
        elseif ($src) { foreach ($p in $src.PSObject.Properties) { $st[$p.Name] = $p.Value } }
    }
    $id = "$GuardId".Trim().ToLowerInvariant()
    $old = if ($st.Contains($id)) { $st[$id] } else { $null }
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } }
    $count = 1; $first = $now.ToString('o'); $lastMail = ''; $sinceMail = 1
    if ($old) {
        $c = 0; [void][int]::TryParse("$(& $g $old 'tripCount')", [ref]$c); $count = $c + 1
        if ("$(& $g $old 'firstSeenUtc')".Trim()) { $first = "$(& $g $old 'firstSeenUtc')" }
        $lastMail = "$(& $g $old 'lastMailUtc')".Trim()
        $s = 0; [void][int]::TryParse("$(& $g $old 'tripsSinceMail')", [ref]$s); $sinceMail = $s + 1
    }
    $mailDue = $false
    if ($CallerMailed) { $lastMail = $now.ToString('o'); $sinceMail = 0 }
    else {
        $lm = $null; if ($lastMail) { try { $lm = ([datetimeoffset]::Parse($lastMail, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { $lm = $null } }
        if (-not $lm -or ($now - $lm).TotalHours -ge $MailDedupHours) { $mailDue = $true }
    }
    $sev = Get-PimGuardSeverity -Outcome $Outcome
    # a later trip that does not say something keeps what an earlier one said (a bare re-trip never blanks the area / action)
    $keep = { param($new, $name) if ("$new".Trim()) { "$new" } else { "$(& $g $old $name)" } }
    $mNew = ConvertTo-PimGuardNumbers $Measured; if (-not $mNew.Count -and $old) { $mNew = ConvertTo-PimGuardNumbers (& $g $old 'measured') }
    $tNew = ConvertTo-PimGuardNumbers $Thresholds; if (-not $tNew.Count -and $old) { $tNew = ConvertTo-PimGuardNumbers (& $g $old 'thresholds') }
    $entry = [ordered]@{
        guardId = $id; outcome = "$Outcome".Trim().ToLowerInvariant(); severity = $sev; area = (& $keep $Area 'area'); job = (& $keep $Job 'job'); title = (& $keep $Title 'title')
        actionText = (& $keep $ActionText 'actionText'); link = (& $keep $Link 'link'); measured = $mNew; thresholds = $tNew
        heldCount = [int]$HeldCount; tripCount = $count; firstSeenUtc = $first; lastSeenUtc = $now.ToString('o')
        lastMailUtc = $lastMail; tripsSinceMail = $sinceMail
        lastSentUtc = "$(& $g $old 'lastSentUtc')"
    }
    $st[$id] = $entry
    return @{ state = $st; entry = $entry; mailDue = $mailDue; sinceMail = $sinceMail }
}

function Select-PimGuardTelemetryDue {
    <# PURE. The guard entries whose last trip is newer than their last send (oldest first). #>
    param([AllowNull()][object]$State)
    $out = @()
    if (-not $State) { return $out }
    $src = if ($State -is [string]) { try { $State | ConvertFrom-Json } catch { $null } } else { $State }
    $items = if ($src -is [System.Collections.IDictionary]) { @($src.Values) } elseif ($src) { @($src.PSObject.Properties | ForEach-Object { $_.Value }) } else { @() }
    foreach ($e in $items) {
        $seen = "$($e.lastSeenUtc)"; $sent = "$($e.lastSentUtc)"
        if (-not $seen) { continue }
        if (-not $sent -or ([datetimeoffset]::Parse($seen, [Globalization.CultureInfo]::InvariantCulture) -gt [datetimeoffset]::Parse($sent, [Globalization.CultureInfo]::InvariantCulture))) { $out += $e }
    }
    return @($out | Sort-Object { "$($_.lastSeenUtc)" })
}

function New-PimGuardUplinkRecord {
    <#
      PURE. One GUARD-1.3 record: Schema 2, Kind 'guard', PascalCase. ActionText (redacted, <= 500) and Link (https) only for
      an IDENTIFIED install; an anonymous one carries the install id and no tenant / text.
    #>
    param([Parameter(Mandatory)][object]$Entry, [ValidateSet('anonymous', 'identified')][string]$Mode = 'anonymous',
          [string]$Product = 'pim-manager', [string]$Version = '', [AllowNull()][object]$Ring, [string]$InstallId = '', [string]$TenantId = '')
    $o = [ordered]@{ Schema = 2; Kind = 'guard'; Product = $Product }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    $gid = "$($Entry.guardId)".Trim().ToLowerInvariant(); if ($gid -notmatch '^[a-z0-9][a-z0-9.-]{0,99}$') { return $null }
    $o['GuardId'] = $gid
    $oc = "$($Entry.outcome)".Trim().ToLowerInvariant(); if ($oc -notin $script:PimGuardOutcomes) { $oc = 'warning' }
    $o['GuardOutcome'] = $oc; $o['Severity'] = Get-PimGuardSeverity -Outcome $oc
    if ("$($Entry.area)".Trim()) { $a = "$($Entry.area)".Trim(); $o['Area'] = $(if ($a.Length -gt 60) { $a.Substring(0, 60) } else { $a }) }
    $j = ("$($Entry.job)".Trim().ToLowerInvariant() -replace '[^a-z0-9.-]', '-') -replace '^[^a-z0-9]+', ''; if ($j.Length -gt 60) { $j = $j.Substring(0, 60) }; if ($j) { $o['Job'] = $j }
    $m = ConvertTo-PimGuardNumbers $Entry.measured; if ($m.Count) { $o['Measured'] = [pscustomobject]$m }
    $t = ConvertTo-PimGuardNumbers $Entry.thresholds; if ($t.Count) { $o['Thresholds'] = [pscustomobject]$t }
    $o['HeldCount'] = [int]("0$($Entry.heldCount)" -replace '[^0-9]', '')
    $o['TripCount'] = [int]("0$($Entry.tripCount)" -replace '[^0-9]', '')
    if ("$($Entry.firstSeenUtc)") { $o['FirstSeenUtc'] = ([datetimeoffset]::Parse("$($Entry.firstSeenUtc)", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Mode -eq 'identified') {
        if ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() }
        $at = "$($Entry.actionText)".Trim()
        if (Get-Command ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $at = ConvertTo-AitUplinkRedacted -Text $at }
        if ($at) { $o['ActionText'] = $(if ($at.Length -gt 500) { $at.Substring(0, 500) } else { $at }) }
        if ("$($Entry.link)" -match '^https://') { $o['Link'] = "$($Entry.link)" }
    } else {
        $o['InstallId'] = "$InstallId"
    }
    $o['LastSeenUtc'] = ([datetimeoffset]::Parse("$($Entry.lastSeenUtc)", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    return [pscustomobject]$o
}

function Invoke-PimGuardTrip {
    <#
      THE call a guard makes when it trips (see the file header). NEVER throws. Returns @{ mailed; mailDue; tripCount; detail }.
      Seams (tests): -GetSetting { param($Name) } / -SetSetting { param($Name, $Value) } / -SendMail { param($Title, $Headline,
      $Detail, $Action) } / -Audit { param($Entry) }. Defaults: the loaded settings / mail / audit functions (engine or Manager).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [Parameter(Mandatory)][ValidateSet('halted', 'refused', 'held', 'skipped', 'warning')][string]$Outcome,
          [string]$Area = '', [string]$Job = '', [string]$Title = '', [string]$Detail = '', [string]$ActionText = '', [string]$Link = '',
          [AllowNull()][object]$Measured, [AllowNull()][object]$Thresholds, [int]$HeldCount = 0, [switch]$CallerMailed,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$MailDedupHours = 24,
          [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null, [scriptblock]$SendMail = $null, [scriptblock]$Audit = $null)
    $res = [ordered]@{ mailed = $false; mailDue = $false; tripCount = 0; detail = '' }
    try {
        if (-not $GetSetting) { $GetSetting = { param($n) if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { Get-PimSetting -Name $n } elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { Get-PimManagerSetting -Name $n } } }
        if (-not $SetSetting) { $SetSetting = { param($n, $v) if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { [void](Set-PimSetting -Name $n -Value $v) } elseif (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { [void](Set-PimManagerSetting -Name $n -Value $v) } } }
        if (-not $SendMail) {
            $SendMail = { param($t, $h, $d, $a)
                if (Get-Command Send-PimSafetyAlert -ErrorAction SilentlyContinue) { $r = Send-PimSafetyAlert -Title $t -Headline $h -Detail $d -Action $a -SwallowScope 'guard-trip-mail' -DebounceMinutes 0; return ("$($r.status)" -in @('sent', 'partial')) }
                if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) { $r = Send-PimManagerAlert -Event 'engine-failure' -Title $t -Detail $d -Headline $h -Action $a -DebounceMinutes 0; return ([int]$r.sent -gt 0) }
                return $false }
        }
        if (-not $Audit) {
            $Audit = { param($e)
                $after = @{ guardId = $e.guardId; outcome = $e.outcome; severity = $e.severity; area = $e.area; job = $e.job; heldCount = $e.heldCount; tripCount = $e.tripCount; measured = $e.measured; thresholds = $e.thresholds }
                if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { Write-PimAuditEvent -Action 'guard.trip' -Target "$($e.guardId)" -After $after }
                elseif (Get-Command Write-PimManagerAuditEvent -ErrorAction SilentlyContinue) { Write-PimManagerAuditEvent -Action 'guard.trip' -Target "$($e.guardId)" -Result 'held' -After $after } }
        }
        $off = $false; try { $off = ("$(& $GetSetting 'GuardAlertMail')".Trim().Trim('"') -match '^(?i)(off|false|0|no)$') } catch { }
        $u = Update-PimGuardTripState -State (& $GetSetting $script:PimGuardSetting) -GuardId $GuardId -Outcome $Outcome -Area $Area -Job $Job -Title $Title `
                -ActionText $ActionText -Link $Link -Measured $Measured -Thresholds $Thresholds -HeldCount $HeldCount -NowUtc $NowUtc -MailDedupHours $MailDedupHours -CallerMailed:$CallerMailed
        $res.tripCount = $u.entry.tripCount; $res.mailDue = [bool]($u.mailDue -and -not $off)
        if ($res.mailDue) {
            $still = if ($u.entry.tripCount -gt 1) { " (still tripping: $($u.entry.tripCount) times since $($u.entry.firstSeenUtc.Substring(0, 16).Replace('T', ' ')) UTC)" } else { '' }
            $sev = if ($u.entry.severity -eq 'critical') { 'Action needed' } else { 'For your attention' }
            $subject = "$sev -- $(if ($Title) { $Title } else { "guard $($u.entry.guardId) tripped" })$still"
            $headline = "PIM4EntraPS protected your data: nothing was lost. $Title"
            $body = [System.Net.WebUtility]::HtmlEncode("$Detail")
            try { $res.mailed = [bool](& $SendMail $subject $headline $body ([System.Net.WebUtility]::HtmlEncode("$ActionText"))) } catch { $res.mailed = $false }
            if ($res.mailed) { $u.entry.lastMailUtc = $NowUtc.ToUniversalTime().ToString('o'); $u.entry.tripsSinceMail = 0 }
        }
        try { & $SetSetting $script:PimGuardSetting ([pscustomobject]$u.state) } catch { $res.detail = "guard state NOT saved: $($_.Exception.Message)" }
        try { & $Audit $u.entry } catch { $res.detail = "$($res.detail) audit NOT written: $($_.Exception.Message)".Trim() }
        try { Write-Host ("  [guard] {0} {1} ({2}) trip #{3}{4}" -f $u.entry.guardId, $u.entry.outcome, $u.entry.severity, $u.entry.tripCount, $(if ($res.mailed) { ' -- mailed' } elseif ($CallerMailed) { ' -- mailed by the guard' } elseif ($off) { ' -- guard mail is off' } elseif (-not $u.mailDue) { ' -- mailed within 24 h, counted' } else { ' -- mail NOT sent' })) -ForegroundColor Yellow } catch { }
    } catch { $res.detail = "guard trip not recorded: $($_.Exception.Message)" }
    return [pscustomobject]$res
}
