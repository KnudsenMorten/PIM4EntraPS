#Requires -Version 5.1
<#
.SYNOPSIS
  OPEN-17 / framework DOCS/REQUIREMENTS.md 8.19 ALERT (owner 2026-11-04 to PIM: "Yes, these three"): a SECURITY FINDING
  reaches Invardia as a Schema 2 Kind 'alert' record -- beside the customer's own alarm (the mail), never instead of it.

.DESCRIPTION
  THE THREE FINDINGS (a literal catalog -- Get-PimUplinkAlertCatalog; a caller can only NAME the event):
    event 'break-glass'  -> AlertId pim.breakglass.used      critical  (the emergency override was switched on)
    event 'drift'        -> AlertId pim.drift.found          warning   (live access differs from what is defined)
    event 'coverage'     -> AlertId pim.coverage.uncovered   warning   (new uncovered roles / groups nobody manages)
  NO NAMES, EVER (owner: "numeric Measured only, no names"):
    * Measured  only the catalog's keys for that AlertId, only NUMBERS (a [string] is dropped even when it looks like
                one -- a name can never ride in), whole and >= 0, at most 10.
    * ActionText a FIXED sentence from the catalog (the caller cannot pass text), redacted, <= 500.
    * Link       the hosted Manager's page for that finding (?tab=settings | drift | coverage) -- never an object id.
    IDENTIFIED ONLY (owner 2026-11-01 "identified only"; Invardia's validator refuses Kind 'alert' from an anonymous sender):
    an anonymous (Community) install sends NO alert record at all -- the cycle skips alerts (no POST, no hold, no refusal)
    and New-PimUplinkAlertRecord gives $null for -Mode anonymous. Findings are still REGISTERED locally (harmless, no
    network); entries older than 48 h are never sent, so a key claimed later does not send old findings.
    Job is a fixed literal per finding: manager (break-glass) | drift-snapshot | coverage.
  HOW IT TRAVELS (the GUARD-1 pattern, PIM-Guard.ps1):
    1. Register-PimUplinkAlert -- called at the SAME point the finding is mailed (the Manager's break-glass switch, the
       drift-snapshot job, the coverage job). It only writes pim.Settings 'UplinkAlerts'; it NEVER throws and never sends,
       so it can never block or fail the engine run or the mail.
    2. Invoke-PimUplinkCycle (job 'uplink') sends every DUE entry (Select-PimUplinkAlertsDue) and marks it sent
       (Save-PimUplinkAlertMarks, a re-read + merge so a finding registered meanwhile is not lost).
  DEBOUNCE (like the mail, 24 h): Count = the repeats inside the 24-hour window that starts at FirstSeenUtc; a repeat after
  that opens a new window (Count 1). An entry is due when it has an unsent repeat AND (it was never sent, OR its window was
  not sent yet, OR the last send is 24 h old) -- so at most the window's first report and then one a day with its Count.
  SWITCH: PIM_UPLINK_ALERTS = 0 / false / off / no -> nothing is registered or sent (Test-PimUplinkAlertsOn; ON otherwise).
  A content refusal from Invardia (400 / 422) holds alerts for 24 h (UplinkState.alertsRefusedUtc) and never stops the
  cycle's other records; the entries stay due and go after the hold.
  ASCII only; PS 5.1-safe; no module, no network in this file.
#>

function Get-PimUplinkAlertSettingName { <# PURE. The pim.Settings name of the alert state (a literal: child-scope safe). #> return 'UplinkAlerts' }

function Test-PimUplinkAlertsOn {
    <# PURE. ON by default; PIM_UPLINK_ALERTS = 0 / false / off / no switches the alert records off. #>
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_ALERTS)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function Get-PimUplinkAlertCatalog {
    <#
      PURE. A LITERAL list (a setting or a caller can never widen it): event -> the alert it reports.
      measured = the ONLY Measured keys this AlertId may carry. tab = the Manager page the Link opens.
    #>
    @(
        [pscustomobject]@{ event = 'break-glass'; alertId = 'pim.breakglass.used'; severity = 'critical'; area = 'breakglass'; job = 'manager'; tab = 'settings'
            measured = @('scopes', 'hours')
            actionText = 'The break-glass emergency override was switched on. Check that this was intended and switch it off in Settings when the emergency is over.' }
        [pscustomobject]@{ event = 'drift'; alertId = 'pim.drift.found'; severity = 'warning'; area = 'drift'; job = 'drift-snapshot'; tab = 'drift'
            measured = @('total', 'missing', 'changed', 'extra')
            actionText = 'Live access differs from what PIM Manager defines. Open the Drift page: apply what should follow the definitions, or ignore what is intended.' }
        [pscustomobject]@{ event = 'coverage'; alertId = 'pim.coverage.uncovered'; severity = 'warning'; area = 'coverage'; job = 'coverage'; tab = 'coverage'
            measured = @('findings', 'gaps', 'orphans', 'unmanagedBindings', 'wrongPermissions', 'unmanagedGroups')
            actionText = 'New privileged roles or groups that nobody manages were found. Open the Discovery and gaps page and add a delegation or mark them as known.' }
    )
}

function Get-PimUplinkAlertSpec {
    <# PURE. The catalog row for an event name OR an AlertId (case-insensitive), or $null. #>
    param([AllowNull()][string]$Name)
    $n = "$Name".Trim().ToLowerInvariant()
    if (-not $n) { return $null }
    return (@(Get-PimUplinkAlertCatalog | Where-Object { $_.event -eq $n -or $_.alertId -eq $n }) | Select-Object -First 1)
}

function Get-PimUplinkAlertId {
    <# PURE. An AlertId as sent: lower-case, ^[a-z0-9][a-z0-9.-]{0,99}$ (framework 8.19) -- or '' (never sent). #>
    param([AllowNull()][object]$Value)
    $id = "$Value".Trim().ToLowerInvariant()
    if ($id -cnotmatch '^[a-z0-9][a-z0-9.-]{0,99}$') { return '' }
    return $id
}

function ConvertTo-PimUplinkAlertMeasured {
    <#
      PURE. Measured as sent: only the -Allowed keys (each ^[a-z][A-Za-z0-9]{0,30}$), only NUMBER values (a string is dropped
      even when it reads as a number -- a name or an id can never become a value), whole and >= 0 (Invardia: safe integers),
      at most 10. Returns an ordered dictionary key -> [long].
    #>
    param([AllowNull()][object]$Values, [string[]]$Allowed = @())
    $o = [ordered]@{}
    if ($null -eq $Values) { return $o }
    $pairs = @()
    try {
        $pairs = if ($Values -is [System.Collections.IDictionary]) { @($Values.Keys | ForEach-Object { [pscustomobject]@{ k = "$_"; v = $Values[$_] } }) }
                 else { @($Values.PSObject.Properties | ForEach-Object { [pscustomobject]@{ k = $_.Name; v = $_.Value } }) }
    } catch { return $o }
    $numTypes = @([int], [long], [int16], [byte], [uint16], [uint32], [uint64], [sbyte], [double], [single], [decimal])
    foreach ($p in @($pairs | Sort-Object k)) {
        if ($o.Count -ge 10) { break }
        $k = "$($p.k)"
        if ($k -cnotmatch '^[a-z][A-Za-z0-9]{0,30}$') { continue }
        if (@($Allowed) -cnotcontains $k) { continue }
        $v = $p.v
        if ($null -eq $v) { continue }
        $isNum = $false; foreach ($t in $numTypes) { if ($v -is $t) { $isNum = $true; break } }
        if (-not $isNum) { continue }
        $d = [double]$v
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d) -or $d -lt 0 -or $d -gt 9007199254740991 -or [math]::Floor($d) -ne $d) { continue }
        $o[$k] = [long]$d
    }
    return $o
}

function Format-PimUplinkAlertUtc {
    <# PURE. A stored time -> 'yyyy-MM-ddTHH:mm:ssZ', or '' (unreadable). #>
    param([AllowNull()][object]$Value)
    $u = $null
    try {
        if ($null -eq $Value -or "$Value" -eq '') { return '' }
        if ($Value -is [datetime]) { $u = $(if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }) }
        elseif ($Value -is [datetimeoffset]) { $u = $Value.UtcDateTime }
        else { $u = [datetimeoffset]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime }
    } catch { return '' }
    return $u.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PimUplinkAlertTime {
    <# PURE. A stored time as a UTC [datetime], or $null. #>
    param([AllowNull()][object]$Value)
    $s = Format-PimUplinkAlertUtc $Value
    if (-not $s) { return $null }
    return [datetime]::SpecifyKind([datetime]::ParseExact($s, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc)
}

function ConvertTo-PimUplinkAlertStateMap {
    <# PURE. pim.Settings 'UplinkAlerts' (an object, a dictionary or JSON text) as an ordered dictionary AlertId -> entry. #>
    param([AllowNull()][object]$State)
    $st = [ordered]@{}
    if ($null -eq $State) { return $st }
    $src = $State
    if ($src -is [string]) { if (-not $src.Trim()) { return $st }; try { $src = $src | ConvertFrom-Json -ErrorAction Stop } catch { return $st } }
    if ($src -is [string]) { try { $src = $src | ConvertFrom-Json -ErrorAction Stop } catch { return $st } }
    if ($null -eq $src) { return $st }
    $names = if ($src -is [System.Collections.IDictionary]) { @($src.Keys) } else { @($src.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $id = Get-PimUplinkAlertId $n
        if (-not $id) { continue }
        $st[$id] = $(if ($src -is [System.Collections.IDictionary]) { $src[$n] } else { $src.$n })
    }
    return $st
}

function Get-PimUplinkAlertEntryField {
    param([AllowNull()][object]$Entry, [string]$Name)
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Collections.IDictionary]) { return $Entry[$Name] }
    $p = $Entry.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Update-PimUplinkAlertState {
    <#
      PURE. The new 'UplinkAlerts' state after one finding of -Event (an event name or an AlertId from the catalog).
      Returns @{ ok; state; entry; reason }. ok = $false (state unchanged) for an event that is not in the catalog.
      Count: repeats inside the 24-hour window from firstSeenUtc; a finding after it opens a new window (Count 1).
      measured = this finding's values (ConvertTo-PimUplinkAlertMeasured over the catalog's keys); lastSentUtc is kept.
    #>
    param([AllowNull()][object]$State, [Parameter(Mandatory)][string]$Event, [AllowNull()][object]$Measured,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$WindowHours = 24)
    $st = ConvertTo-PimUplinkAlertStateMap $State
    $spec = Get-PimUplinkAlertSpec $Event
    if (-not $spec) { return @{ ok = $false; state = $st; entry = $null; reason = "'$Event' is not an uplink alert" } }
    $id = Get-PimUplinkAlertId $spec.alertId
    if (-not $id) { return @{ ok = $false; state = $st; entry = $null; reason = 'the catalog AlertId does not fit the rule' } }
    if ($WindowHours -le 0) { $WindowHours = 24 }
    $now = $NowUtc.ToUniversalTime()
    $old = $null; if ($st.Contains($id)) { $old = $st[$id] }
    $first = $now; $count = 1
    if ($null -ne $old) {
        $of = ConvertTo-PimUplinkAlertTime (Get-PimUplinkAlertEntryField $old 'firstSeenUtc')
        $oc = 0; [void][int]::TryParse("$(Get-PimUplinkAlertEntryField $old 'count')", [ref]$oc)
        if ($null -ne $of -and $of -le $now -and ($now - $of).TotalHours -lt $WindowHours -and $oc -ge 1) { $first = $of; $count = $oc + 1 }
    }
    $entry = [ordered]@{
        alertId = $id; severity = "$($spec.severity)"; area = "$($spec.area)"; job = "$($spec.job)"
        measured = (ConvertTo-PimUplinkAlertMeasured -Values $Measured -Allowed @($spec.measured))
        firstSeenUtc = $first.ToString('o'); lastSeenUtc = $now.ToString('o'); count = [int]$count
        lastSentUtc = (Format-PimUplinkAlertUtc (Get-PimUplinkAlertEntryField $old 'lastSentUtc'))
    }
    $st[$id] = $entry
    return @{ ok = $true; state = $st; entry = $entry; reason = '' }
}

function Select-PimUplinkAlertsDue {
    <#
      PURE. The entries to send now (oldest finding first): an unsent repeat (lastSeenUtc newer than lastSentUtc) AND
      (never sent, OR this window was not sent yet -- lastSentUtc before firstSeenUtc --, OR the last send is >= 24 h old).
      Entries whose AlertId is not in the catalog, and entries last seen more than -MaxAgeHours (48) ago (a finding recorded
      while the install was anonymous / off is not sent days later), are left out.
    #>
    param([AllowNull()][object]$State, [datetime]$NowUtc = [datetime]::UtcNow, [int]$RepeatHours = 24, [int]$MaxAgeHours = 48)
    $out = New-Object System.Collections.Generic.List[object]
    $now = $NowUtc.ToUniversalTime()
    $st = ConvertTo-PimUplinkAlertStateMap $State
    foreach ($id in @($st.Keys)) {
        $e = $st[$id]
        if ($null -eq $e -or -not (Get-PimUplinkAlertSpec $id)) { continue }
        $seen = ConvertTo-PimUplinkAlertTime (Get-PimUplinkAlertEntryField $e 'lastSeenUtc')
        if ($null -eq $seen) { continue }
        if ($MaxAgeHours -gt 0 -and ($now - $seen).TotalHours -gt $MaxAgeHours) { continue }
        $sent =ConvertTo-PimUplinkAlertTime (Get-PimUplinkAlertEntryField $e 'lastSentUtc')
        if ($null -eq $sent) { $out.Add($e); continue }
        if ($seen -le $sent) { continue }
        $first = ConvertTo-PimUplinkAlertTime (Get-PimUplinkAlertEntryField $e 'firstSeenUtc')
        if (($null -ne $first -and $sent -lt $first) -or ($now - $sent).TotalHours -ge $RepeatHours) { $out.Add($e) }
    }
    return @($out.ToArray() | Sort-Object { Format-PimUplinkAlertUtc (Get-PimUplinkAlertEntryField $_ 'lastSeenUtc') })
}

function Get-PimUplinkAlertLink {
    <#
      PURE. The hosted Manager's page for this alert: <ManagerUrl>/?tab=<catalog tab>. '' when no usable Manager address is
      known (https, a DNS host with a dot, no query / fragment / user, never an '.internal.' / localhost / .local host).
    #>
    param([AllowNull()][string]$AlertId, [string]$ManagerUrl = '')
    $spec = Get-PimUplinkAlertSpec $AlertId
    if (-not $spec -or "$($spec.tab)" -notmatch '^[a-z-]{1,30}$') { return '' }
    $b = "$ManagerUrl".Trim().Trim('"').TrimEnd('/')
    if (-not $b -or $b.Length -gt 300 -or $b -notmatch '^(?i)https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$') { return '' }
    $u = $null; if (-not [Uri]::TryCreate($b, [UriKind]::Absolute, [ref]$u)) { return '' }
    $h = $u.Host.ToLowerInvariant()
    if ($u.HostNameType -ne [UriHostNameType]::Dns -or $h -notmatch '\.' -or $h -match '(^|\.)internal(\.|$)' -or $h -match '(^|\.)localhost$' -or $h -match '\.local$') { return '' }
    $l = "$b/?tab=$($spec.tab)"
    if ($l.Length -gt 400) { return '' }
    return $l
}

function New-PimUplinkAlertRecord {
    <#
      PURE. One framework 8.19 record: Schema 2, Kind 'alert', PascalCase -- Product, Version, Ring, AlertId, Severity,
      Measured (numbers only), FirstSeenUtc, Count, Area, Job, LastSeenUtc, ClaimedTenantId, ActionText (the catalog's
      sentence, redacted, <= 500) and Link (https). IDENTIFIED ONLY (owner 2026-11-01 "identified only"; Invardia refuses
      Kind 'alert' from an anonymous sender): -Mode anonymous gives $null -- there is no anonymous alert record.
      Every value is taken from the CATALOG by the entry's AlertId -- never the entry's own text. $null when the AlertId does
      not fit ^[a-z0-9][a-z0-9.-]{0,99}$ or is not in the catalog, or the entry has no readable first-seen time.
    #>
    param([Parameter(Mandatory)][AllowNull()][object]$Entry, [ValidateSet('anonymous', 'identified')][string]$Mode = 'identified',
          [string]$Product = 'pim-manager', [string]$Version = '', [AllowNull()][object]$Ring, [string]$TenantId = '',
          [string]$ManagerUrl = '')
    if ($null -eq $Entry -or $Mode -ne 'identified') { return $null }
    $id = Get-PimUplinkAlertId (Get-PimUplinkAlertEntryField $Entry 'alertId')
    if (-not $id) { return $null }
    $spec = Get-PimUplinkAlertSpec $id
    if (-not $spec -or $spec.alertId -ne $id) { return $null }
    $sev = "$($spec.severity)"; if ($sev -notin @('critical', 'warning')) { return $null }
    $fs = Format-PimUplinkAlertUtc (Get-PimUplinkAlertEntryField $Entry 'firstSeenUtc'); if (-not $fs) { return $null }
    $o = [ordered]@{ Schema = 2; Kind = 'alert'; Product = $Product }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    $o['AlertId'] = $id; $o['Severity'] = $sev
    $m = ConvertTo-PimUplinkAlertMeasured -Values (Get-PimUplinkAlertEntryField $Entry 'measured') -Allowed @($spec.measured)
    if ($m.Count) { $o['Measured'] = [pscustomobject]$m }
    $o['FirstSeenUtc'] = $fs
    $c = 0; [void][int]::TryParse("$(Get-PimUplinkAlertEntryField $Entry 'count')", [ref]$c); if ($c -lt 1) { $c = 1 }
    $o['Count'] = [int]$c
    if ("$($spec.area)" -match '^[a-z0-9][a-z0-9.-]{0,59}$') { $o['Area'] = "$($spec.area)" }
    if ("$($spec.job)" -match '^[a-z0-9][a-z0-9.-]{0,59}$') { $o['Job'] = "$($spec.job)" }
    if ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() }
    $at = "$($spec.actionText)".Trim()
    if (Get-Command ConvertTo-AitUplinkRedacted -ErrorAction SilentlyContinue) { $at = "$(ConvertTo-AitUplinkRedacted -Text $at)".Trim() }
    $at = $at -replace '[\x00-\x1F\x7F]', ' '
    if ($at.Length -gt 500) { $at = $at.Substring(0, 500) }
    if ($at) { $o['ActionText'] = $at }
    $lk = ''; try { $lk = Get-PimUplinkAlertLink -AlertId $id -ManagerUrl $ManagerUrl } catch { $lk = '' }
    if ($lk) { $o['Link'] = $lk }
    $ls = Format-PimUplinkAlertUtc (Get-PimUplinkAlertEntryField $Entry 'lastSeenUtc'); if ($ls) { $o['LastSeenUtc'] = $ls }
    return [pscustomobject]$o
}

function Register-PimUplinkAlert {
    <#
      THE call at the point a finding is mailed. Records it in pim.Settings 'UplinkAlerts' for the next uplink cycle.
      NEVER throws and never sends (best effort: a store that fails is reported in the result, nothing else happens).
      -Event  'break-glass' | 'drift' | 'coverage' (or the AlertId).   -Measured  @{ key = number } (catalog keys only).
      Seams (tests): -GetSetting { param($Name) } / -SetSetting { param($Name, $Value) }; defaults: the loaded settings
      functions (engine or Manager). Returns @{ registered; alertId; count; reason }.
    #>
    param([Parameter(Mandatory)][string]$Event, [AllowNull()][object]$Measured, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null, [AllowNull()][object]$Enabled = $null)
    $res = [ordered]@{ registered = $false; alertId = ''; count = 0; reason = '' }
    try {
        $on = if ($null -ne $Enabled) { [bool]$Enabled } else { Test-PimUplinkAlertsOn }
        if (-not $on) { $res.reason = 'uplink alerts are off (PIM_UPLINK_ALERTS)'; return [pscustomobject]$res }
        if (-not $GetSetting) { $GetSetting = { param($n) if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { Get-PimSetting -Name $n } elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { Get-PimManagerSetting -Name $n } } }
        if (-not $SetSetting) { $SetSetting = { param($n, $v) if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { [void](Set-PimSetting -Name $n -Value $v) } elseif (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { [void](Set-PimManagerSetting -Name $n -Value $v) } else { throw 'no settings store is loaded in this process' } } }
        $u = Update-PimUplinkAlertState -State (& $GetSetting (Get-PimUplinkAlertSettingName)) -Event $Event -Measured $Measured -NowUtc $NowUtc
        if (-not $u.ok) { $res.reason = "$($u.reason)"; return [pscustomobject]$res }
        & $SetSetting (Get-PimUplinkAlertSettingName) ([pscustomobject]$u.state)
        $res.registered = $true; $res.alertId = "$($u.entry.alertId)"; $res.count = [int]$u.entry.count
    } catch { $res.registered = $false; $res.reason = "uplink alert not recorded: $($_.Exception.Message)" }
    try { if (-not $res.registered -and $res.reason -and $res.reason -notmatch 'are off') { Write-Warning "[uplink-alert] $($res.reason)" } } catch { }
    return [pscustomobject]$res
}

function Save-PimUplinkAlertMarks {
    <#
      After a cycle: lastSentUtc = -SentUtc on each -AlertIds entry, on a FRESH read of 'UplinkAlerts' (a finding the Manager
      or a job registered during the cycle is kept). Returns '' or the reason it was not saved. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting, [string[]]$AlertIds = @(),
          [datetime]$SentUtc = [datetime]::UtcNow)
    try {
        $ids = @(@($AlertIds) | ForEach-Object { Get-PimUplinkAlertId $_ } | Where-Object { $_ })
        if (-not $ids.Count) { return '' }
        $st = ConvertTo-PimUplinkAlertStateMap (& $GetSetting (Get-PimUplinkAlertSettingName))
        $n = 0
        foreach ($id in $ids) {
            if (-not $st.Contains($id) -or $null -eq $st[$id]) { continue }
            $e = $st[$id]
            $copy = [ordered]@{}
            if ($e -is [System.Collections.IDictionary]) { foreach ($k in $e.Keys) { $copy["$k"] = $e[$k] } } else { foreach ($p in $e.PSObject.Properties) { $copy[$p.Name] = $p.Value } }
            $copy['lastSentUtc'] = $SentUtc.ToUniversalTime().ToString('o')
            $st[$id] = $copy; $n++
        }
        if ($n) { & $SetSetting (Get-PimUplinkAlertSettingName) ([pscustomobject]$st) }
        return ''
    } catch { return "alert send marks not saved: $($_.Exception.Message)" }
}
