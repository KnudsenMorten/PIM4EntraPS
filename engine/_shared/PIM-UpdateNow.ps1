#Requires -Version 5.1
<#
.SYNOPSIS
  "UPDATE NOW" for a ring / an environment (framework DOCS/REQUIREMENTS.md 8.18 UPDATE-NOW; PIM docs/REQUIREMENTS.md
  33.0 bullet '"UPDATE NOW" FOR A RING / AN ENVIRONMENT'; agreed SI + PIM + Invardia 2026-10-16, owner: "i like it").

.DESCRIPTION
  PIM's tick has no right to start the updater, and a no-contact install (framework 12.23 P9) can never be given one -- so
  the UPDATER (ca-pim-update, tools/pim-engine/update-job-entry.ps1) reads the signal ITSELF:

    * its cron becomes every 15 minutes, on the minutes of its nightly time ('40 3 * * *' -> '10,25,40,55 * * * *'), and
      the nightly time is kept on the job as PIM_UPDATE_NIGHTLY_UTC ('03:40'). No PIM_UPDATE_NIGHTLY_UTC = the job is
      still on its nightly cron: every execution is a full run, exactly as before (Get-PimUpdaterRunKind 'legacy').
    * each execution decides what it is (Get-PimUpdaterRunKind):
        nightly  it started inside the nightly slot -> the normal update, exactly as before
        manual   it did not start on a 15-minute slot, or the slot's scheduled execution already ran (somebody started
                 it: ops, the updater's own follow-up run) -> the normal update, exactly as before
        quick    the slot's scheduled execution -> ONLY the signal check (seconds), then exit 0 with one line -- unless
                 the signal says "now" for a version the ring approves, then the normal update runs in this execution
    * the signal: GET <base>/api/updates/pim-manager/signal?ring=N, header X-Invardia-Install-Key, If-None-Match
      -> 200 { updateNow; version; raisedAt; by; scope: ring|environment } + ETag, 304 unchanged. 404 / unreachable /
      anything else = "no signal", quietly (Invardia may not be live yet) -- never an error run.
    * the signal says NOW, never WHICH version: the version the ring approves (the signed manifest / channel.json) stays
      the authority (Get-PimUpdateNowApprovalDecision), and every block of the nightly run still applies.
    * at most ONE update per raisedAt (marked BEFORE the update starts); a failed update is not retried by the signal (the
      nightly run retries); none while another execution of the updater is running; a signal older than 24 h is ignored.

  UPDATE-NOW-HEAD (Invardia 2026-11-03, Invardia DESIGN 12 "Quicker updates"; owner rule 2026-10-12) -- the quick check
  now asks first:
      POST <base>/api/updates/pim-manager/head   headers X-Invardia-Install-Key [+ X-Invardia-Install-Id]
           body { kind: 'code'; licence: <the licence text, as the manifest pull sends it>; ring }   (writes nothing)
      -> 200 { version; sequence; wave?; expedite?: { apply: now|window; until; reason } }
         401 key / 403 licence|installKeyBound|ring / 422 invalid = do nothing, ONE line naming the refusal.
      * expedite.apply 'now' + a version newer than installed -> the update runs in this slot (the existing path).
      * 'window' -> only inside the install's update window (PIM_UPDATE_WINDOW 'HH:MM-HH:MM' UTC on the updater job; the
        default is the hour of the nightly slot, Get-PimUpdateWindowDefault), and never after 'until'.
      * no expedite / not newer -> nothing (the nightly run covers it).
      * 404 = an older Invardia without /head -> the old GET /signal (below) ONCE in this run, so the deploy order does not
        matter. 0 / 429 / 5xx = no answer, quietly; NO retry here -- the next 15-minute slot is the retry.
      * "at most once": a head expedite has no raisedAt -- the first time THIS updater saw it (version + sequence + apply)
        stands in for it, so the once-per-raisedAt rule below is unchanged.
      * the licence text and the install key are never written to a line, the store or the heartbeat.

  [!] OFF by default behind a per-ring switch (framework 8.18 "built OFF behind a per-ring switch, ring 0 first"):
     Get-PimUpdateNowDefaultRings (a literal: ring 0) unless PIM_UPDATE_NOW on the updater job says 1/0.
  [!] The heartbeat's UpdatePending { signal; raisedAt; startedUtc }: ON by default since UPDATE-NOW-HEAD;
     PIM_UPLINK_UPDATENOWFIELDS = 0/false/off/no switches the three fields off.

  State: pim.Settings 'UpdateNowState' { etag; signal { updateNow; version; raisedAt; scope }; handledRaisedAt;
  handledVersion; startedUtc; lastResult; changedUtc } -- written only when something in it changes.
  PURE except Invoke-PimUpdateNowQuickCheck / Set-PimUpdateNowHandled, whose I/O is injected (seams). ASCII; 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimUpdateNowDefaultRings {
    <# PURE. LITERAL (child-scope safe). The rings UPDATE NOW is on for by default. UPDATE-NOW-ALL-RINGS (Invardia 2026-11-05,
       binding; 13 ring-2 installs sat on 3.0.40 all day because their updater looked only at 03:00Z): EVERY ring -- the
       15-minute signal check is PIM's default in setup AND the updater; PIM_UPDATE_NOW=0 on a job still switches it off. #>
    return @(0, 1, 2, 3)
}
function Get-PimUpdateNowMaxAgeHours  { <# PURE. LITERAL. A signal older than this is ignored (Invardia clears it after 24 h). #> return 24 }
function Get-PimUpdateNowStaleRunHours { <# PURE. LITERAL. A 'Running' updater execution older than this is presumed hung. #> return 6 }
function Get-PimUpdateNowSlotMinutes  { <# PURE. LITERAL. The cadence of the updater's cron when UPDATE NOW is on. #> return 15 }
function Get-PimUpdateNowStateName    { <# PURE. LITERAL. #> return 'UpdateNowState' }

function Test-PimUpdateNowEnabled {
    <#
      PURE. Is UPDATE NOW on for this environment? -Value = PIM_UPDATE_NOW on the updater job: 1/true/on/yes = on,
      0/false/off/no = off, anything else (unset) = on only when -Ring is one of Get-PimUpdateNowDefaultRings.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Ring, [AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if ($v -match '^(?i)(1|true|on|yes)$') { return $true }
    if ($v -match '^(?i)(0|false|off|no)$') { return $false }
    $n = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$n)) { return $false }
    return [bool](@(Get-PimUpdateNowDefaultRings) -contains $n)
}

function Test-PimUpdateNowFieldsOn {
    <# PURE. PIM_UPLINK_UPDATENOWFIELDS: ON by default (UPDATE-NOW-HEAD) -- an off-switch: only 0/false/off/no switches the
       three UpdatePending fields off; unset or anything else = on. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    return (-not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$'))
}

# ---- UPDATE-NOW-HEAD: the install's update window ----------------------------------------------------------------------
function Get-PimUpdateWindowDefault {
    <#
      PURE. LITERAL default (child-scope safe) of the update window when PIM_UPDATE_WINDOW is unset or unreadable: the HOUR
      of the nightly slot, 'HH:00-HH+1:00' UTC (nightly '03:40' -> '03:00-04:00'). No readable nightly time = the setup
      default ('0 3 * * *') -> '03:00-04:00'.
    #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyUtc)
    $n = ConvertFrom-PimUpdateNowNightly -Text $NightlyUtc
    $h = 3; if ($n.ok) { $h = $n.hour }
    return ('{0:D2}:00-{1:D2}:00' -f $h, (($h + 1) % 24))
}

function ConvertFrom-PimUpdateWindow {
    <# PURE. 'HH:MM-HH:MM' (UTC; may cross midnight, '24:00' allowed as an end) -> @{ ok; startMin; endMin; text }. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $bad = @{ ok = $false; startMin = -1; endMin = -1; text = '' }
    $t = ("$Text".Trim() -replace '\s+', '')
    if ($t -notmatch '^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$') { return $bad }
    $a = [int]$Matches[1]; $b = [int]$Matches[2]; $c = [int]$Matches[3]; $d = [int]$Matches[4]
    if ($a -gt 23 -or $b -gt 59 -or $c -gt 24 -or $d -gt 59 -or ($c -eq 24 -and $d -ne 0)) { return $bad }
    $s = $a * 60 + $b; $e = $c * 60 + $d
    if ($s -eq ($e % 1440)) { return $bad }
    return @{ ok = $true; startMin = $s; endMin = $e; text = ('{0:D2}:{1:D2}-{2:D2}:{3:D2}' -f $a, $b, $c, $d) }
}

function Get-PimUpdateWindowState {
    <#
      PURE. Is -NowUtc inside the install's update window? -Window = PIM_UPDATE_WINDOW on the updater job ('' = the default,
      Get-PimUpdateWindowDefault from -NightlyUtc). Returns @{ open; text; source = setting|default; note }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Window, [AllowNull()][AllowEmptyString()][string]$NightlyUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    $src = 'setting'; $note = ''
    $w = ConvertFrom-PimUpdateWindow -Text $Window
    if (-not $w.ok) {
        $raw = "$Window".Trim(); if ($raw.Length -gt 40) { $raw = $raw.Substring(0, 40) }
        if ($raw) { $note = "PIM_UPDATE_WINDOW '$raw' is not 'HH:MM-HH:MM' -- the default is used" }
        $src = 'default'; $w = ConvertFrom-PimUpdateWindow -Text (Get-PimUpdateWindowDefault -NightlyUtc $NightlyUtc)
    }
    $n = $NowUtc.ToUniversalTime(); $m = $n.Hour * 60 + $n.Minute
    $open = if ($w.startMin -lt $w.endMin) { ($m -ge $w.startMin -and $m -lt $w.endMin) } else { ($m -ge $w.startMin -or $m -lt $w.endMin) }
    return @{ open = [bool]$open; text = $w.text; source = $src; note = $note }
}

function Compare-PimUpdateNowVersion {
    <# PURE. 1 / 0 / -1 by the numeric parts ('2.4.645' vs '2.4.99'); $null when either is not a dotted number. #>
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $pa = "$A".Trim().TrimStart('v', 'V'); $pb = "$B".Trim().TrimStart('v', 'V')
    if ($pa -notmatch '^\d+(\.\d+){0,5}$' -or $pb -notmatch '^\d+(\.\d+){0,5}$') { return $null }
    $xa = @($pa -split '\.'); $xb = @($pb -split '\.')
    $n = [Math]::Max($xa.Count, $xb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $va = [int64]0; $vb = [int64]0
        if ($i -lt $xa.Count) { $va = [int64]$xa[$i] }
        if ($i -lt $xb.Count) { $vb = [int64]$xb[$i] }
        if ($va -gt $vb) { return 1 }
        if ($va -lt $vb) { return -1 }
    }
    return 0
}

function ConvertTo-PimUpdateNowUtc {
    # PURE. A stored / answered time as UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    try {
        if ($null -eq $Value) { return $null }
        if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
        if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
        $s = "$Value".Trim(); if (-not $s) { return $null }
        return [datetimeoffset]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
    } catch { return $null }
}

function ConvertTo-PimUpdateNowIso {
    # PURE. A stored time back as round-trip ISO UTC text ('' when none). NEVER "$value": PowerShell 7's ConvertFrom-Json
    # hands a [datetime] back, and its string form is culture-formatted without the fraction -- a raisedAt kept that way
    # would no longer equal the signal's, and the same signal would be acted on twice.
    param([AllowNull()][object]$Value)
    $t = ConvertTo-PimUpdateNowUtc $Value
    if ($null -eq $t) { return '' }
    return $t.ToString('o')
}

function Get-PimUpdateNowField {
    # PURE. A property of an object or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertFrom-PimUpdateNowStored {
    # PURE. A stored setting (an object, or JSON text -- twice encoded too) as an object, or $null.
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        $t = "$v".Trim(); if (-not $t) { return $null }
        try { $v = $t | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    }
    return $v
}

# ---- the cron -------------------------------------------------------------------------------------------------------
function ConvertFrom-PimUpdateNowNightly {
    <# PURE. 'HH:mm' (UTC) -> @{ ok; hour; minute; text }. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text".Trim()
    if ($t -notmatch '^(\d{1,2}):(\d{2})$') { return @{ ok = $false; hour = -1; minute = -1; text = '' } }
    $h = [int]$Matches[1]; $m = [int]$Matches[2]
    if ($h -gt 23 -or $m -gt 59) { return @{ ok = $false; hour = -1; minute = -1; text = '' } }
    return @{ ok = $true; hour = $h; minute = $m; text = ('{0:D2}:{1:D2}' -f $h, $m) }
}

function Get-PimUpdateNowQuarterCron {
    <# PURE. The 15-minute cron on the minutes of a nightly minute: 0 -> '0,15,30,45 * * * *', 40 -> '10,25,40,55 * * * *'. #>
    param([ValidateRange(0, 59)][int]$Minute)
    $o = $Minute % 15
    return ('{0},{1},{2},{3} * * * *' -f $o, ($o + 15), ($o + 30), ($o + 45))
}

function Get-PimUpdateNowCronPlan {
    <#
      PURE. A nightly cron ('M H * * *', the only shape the updater has ever been deployed with) -> @{ ok; nightlyUtc
      ('HH:mm'); quarterCron; nightlyCron; reason }. Any other shape -> ok = $false: the job keeps that cron, every execution
      a full run, and UPDATE NOW cannot be used there (said in reason).
    #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyCron)
    $c = ("$NightlyCron".Trim() -replace '\s+', ' ')
    $res = @{ ok = $false; nightlyUtc = ''; quarterCron = ''; nightlyCron = $c; reason = '' }
    if ($c -notmatch '^(\d{1,2}) (\d{1,2}) \* \* \*$') { $res.reason = "the updater's cron '$c' is not a daily 'M H * * *' -- it is kept, and UPDATE NOW needs a daily one"; return $res }
    $m = [int]$Matches[1]; $h = [int]$Matches[2]
    if ($m -gt 59 -or $h -gt 23) { $res.reason = "the updater's cron '$c' is not a valid time"; return $res }
    $res.ok = $true; $res.nightlyUtc = ('{0:D2}:{1:D2}' -f $h, $m); $res.quarterCron = Get-PimUpdateNowQuarterCron -Minute $m
    $res.nightlyCron = ('{0} {1} * * *' -f $m, $h)
    $res.reason = "nightly at $($res.nightlyUtc) UTC; every 15 minutes = '$($res.quarterCron)'"
    return $res
}

function Get-PimUpdateNowSelfCronPlan {
    <#
      PURE. What the UPDATER does with ITS OWN job's cron on a full run (an existing install converges here; it already holds
      Contributor on its resource group -- the right that rolls the Manager and stamps its own image).
        -CurrentCron   the job's cronExpression now          -NightlyUtc  PIM_UPDATE_NIGHTLY_UTC on the job ('' = none)
        -Enabled       Test-PimUpdateNowEnabled for this environment
      Returns @{ action = none|quarter|nightly; cron; nightlyUtc; reason }:
        quarter  on, and the job is on a daily cron         -> cron = the 15-minute cron, nightlyUtc = that daily time
                 on, a 15-minute cron with no nightly time  -> none (it cannot tell the nightly slot; said in reason)
        nightly  OFF, and the job is on its 15-minute cron  -> back to the daily cron at PIM_UPDATE_NIGHTLY_UTC
        none     everything else (already right)
    #>
    param([AllowNull()][AllowEmptyString()][string]$CurrentCron, [AllowNull()][AllowEmptyString()][string]$NightlyUtc, [bool]$Enabled)
    $cur = ("$CurrentCron".Trim() -replace '\s+', ' ')
    $n = ConvertFrom-PimUpdateNowNightly -Text $NightlyUtc
    $daily = Get-PimUpdateNowCronPlan -NightlyCron $cur
    $isQuarter = [bool]($cur -match '^\d{1,2},\d{1,2},\d{1,2},\d{1,2} \* \* \* \*$')
    if ($Enabled) {
        if ($daily.ok) { return @{ action = 'quarter'; cron = $daily.quarterCron; nightlyUtc = $daily.nightlyUtc; reason = "UPDATE NOW is on: the updater checks every 15 minutes ($($daily.reason))" } }
        if ($isQuarter -and $n.ok) {
            $want = Get-PimUpdateNowQuarterCron -Minute $n.minute
            if ($cur -eq $want) { return @{ action = 'none'; cron = $cur; nightlyUtc = $n.text; reason = "every 15 minutes, nightly at $($n.text) UTC" } }
            return @{ action = 'quarter'; cron = $want; nightlyUtc = $n.text; reason = "the 15-minute cron did not match the nightly time $($n.text) -- corrected" }
        }
        if ($isQuarter) { return @{ action = 'none'; cron = $cur; nightlyUtc = ''; reason = 'a 15-minute cron with no nightly time (PIM_UPDATE_NIGHTLY_UTC) -- left as it is; re-run Deploy-PimUpdateJob' } }
        return @{ action = 'none'; cron = $cur; nightlyUtc = ''; reason = $daily.reason }
    }
    if ($isQuarter -and $n.ok) {
        return @{ action = 'nightly'; cron = ('{0} {1} * * *' -f $n.minute, $n.hour); nightlyUtc = $n.text; reason = "UPDATE NOW is off: back to the nightly cron at $($n.text) UTC" }
    }
    return @{ action = 'none'; cron = $cur; nightlyUtc = $n.text; reason = 'UPDATE NOW is off -- the cron is left as it is' }
}

# ---- which kind of execution is this ---------------------------------------------------------------------------------
function ConvertTo-PimUpdateNowExecutions {
    # PURE. ARM executions (value[] or a list) -> @{ name; status; startUtc; endUtc } objects.
    param([AllowNull()][object]$Items)
    if ($null -eq $Items) { return $null }
    $list = @(if ($Items.PSObject.Properties['value']) { $Items.value } else { $Items })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($list | Where-Object { $null -ne $_ })) {
        $props = Get-PimUpdateNowField $x 'properties'
        $st = if ($null -ne $props) { Get-PimUpdateNowField $props 'status' } else { Get-PimUpdateNowField $x 'status' }
        $t  = if ($null -ne $props) { Get-PimUpdateNowField $props 'startTime' } else { Get-PimUpdateNowField $x 'startTime' }
        $te = if ($null -ne $props) { Get-PimUpdateNowField $props 'endTime' } else { Get-PimUpdateNowField $x 'endTime' }   # SCHEMA-QUIESCE-LONG-SNAPSHOT: a job's usual length
        $out.Add([pscustomobject]@{ name = "$(Get-PimUpdateNowField $x 'name')".Trim(); status = "$st".Trim(); startUtc = (ConvertTo-PimUpdateNowUtc $t); endUtc = (ConvertTo-PimUpdateNowUtc $te) }) | Out-Null
    }
    return @($out.ToArray())
}

function Get-PimUpdaterRunKind {
    <#
      PURE. @{ kind = legacy|nightly|manual|quick; reason; startUtc; slotUtc }.
        -NightlyUtc       PIM_UPDATE_NIGHTLY_UTC ('' = the job is on its nightly cron -> legacy: a full run, as before)
        -StartUtc         when THIS execution started (its ARM startTime; else the process start, with a wider -ToleranceSeconds)
        -Executions       the job's executions (ConvertTo-PimUpdateNowExecutions); $null = not readable
        -OwnExecution     CONTAINER_APP_JOB_EXECUTION_NAME
        -Enabled          Test-PimUpdateNowEnabled ($false = legacy: every execution a full run)
      A scheduled execution starts on a 15-minute slot (the nightly minute's quarter-hour minutes), within -ToleranceSeconds.
      Off-slot, or not the FIRST execution of its slot (the scheduled one already ran) = somebody started it = manual.
    #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyUtc, [Parameter(Mandatory)][datetime]$StartUtc, [AllowNull()][object[]]$Executions = $null,
          [AllowNull()][AllowEmptyString()][string]$OwnExecution = '', [int]$ToleranceSeconds = 120, [bool]$Enabled = $true)
    $n = ConvertFrom-PimUpdateNowNightly -Text $NightlyUtc
    $s = $StartUtc.ToUniversalTime()
    if (-not $n.ok) { return @{ kind = 'legacy'; reason = 'the updater runs on its nightly cron (no PIM_UPDATE_NIGHTLY_UTC) -- a full run, as before'; startUtc = $s; slotUtc = $null } }
    # OFF = every execution is a full run, as before (a hand-started run must never become a quick check that does nothing;
    # a job still on its 15-minute cron gets its nightly cron back from that full run -- Invoke-PimUpdateNowSelfCronUpdate).
    if (-not $Enabled) { return @{ kind = 'legacy'; reason = 'update now is off for this environment -- a full run, as before'; startUtc = $s; slotUtc = $null } }
    $q = Get-PimUpdateNowSlotMinutes
    $o = $n.minute % $q
    $back = (($s.Minute - $o) % $q + $q) % $q
    $slot = (New-Object datetime ($s.Year, $s.Month, $s.Day, $s.Hour, $s.Minute, 0, [DateTimeKind]::Utc)).AddMinutes(-$back)
    if ($slot.Hour -eq $n.hour -and $slot.Minute -eq $n.minute) {
        return @{ kind = 'nightly'; reason = "the nightly slot ($($n.text) UTC) -- the normal update"; startUtc = $s; slotUtc = $slot }
    }
    $delta = ($s - $slot).TotalSeconds
    if ($delta -gt $ToleranceSeconds) {
        return @{ kind = 'manual'; reason = ("started off the 15-minute schedule ({0:HH:mm:ss} UTC) -- started by hand: the normal update" -f $s); startUtc = $s; slotUtc = $slot }
    }
    $own = "$OwnExecution".Trim()
    foreach ($e in @($Executions | Where-Object { $null -ne $_ })) {
        if ($own -and "$($e.name)" -eq $own) { continue }
        $t = $e.startUtc
        if ($null -ne $t -and $t -ge $slot -and $t -lt $s) {
            return @{ kind = 'manual'; reason = ("the {0:HH:mm} UTC slot already had its scheduled execution ({1}) -- this one was started by hand: the normal update" -f $slot, "$($e.name)"); startUtc = $s; slotUtc = $slot }
        }
    }
    return @{ kind = 'quick'; reason = ("the {0:HH:mm} UTC 15-minute check" -f $slot); startUtc = $s; slotUtc = $slot }
}

function Get-PimUpdateNowOtherRunning {
    <#
      PURE. Is ANOTHER execution of the updater running? $true / $false, $null when -Executions is $null (not readable).
      Running / Processing / Unknown count, unless they started more than Get-PimUpdateNowStaleRunHours ago (a hung run
      must not block every update for the job's 7-day run limit).
    #>
    param([AllowNull()][object[]]$Executions, [AllowNull()][AllowEmptyString()][string]$OwnExecution = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Executions) { return $null }
    $own = "$OwnExecution".Trim()
    $stale = Get-PimUpdateNowStaleRunHours
    foreach ($e in @($Executions | Where-Object { $null -ne $_ })) {
        if ($own -and "$($e.name)" -eq $own) { continue }
        if ("$($e.status)" -notmatch '^(?i)(Running|Processing|Unknown)$') { continue }
        if ($null -ne $e.startUtc -and ($NowUtc.ToUniversalTime() - $e.startUtc).TotalHours -ge $stale) { continue }
        return $true
    }
    return $false
}

# ---- the signal ------------------------------------------------------------------------------------------------------
function ConvertFrom-PimUpdateNowSignal {
    <# PURE. Invardia's answer body -> @{ ok; updateNow; version; raisedAt (UTC or $null); scope (ring|environment); by }. #>
    param([AllowNull()][object]$Body)
    $b = ConvertFrom-PimUpdateNowStored $Body
    $res = @{ ok = $false; updateNow = $false; version = ''; raisedAt = $null; scope = ''; by = '' }
    if ($null -eq $b) { return $res }
    $res.ok = $true
    $u = Get-PimUpdateNowField $b 'updateNow'
    $res.updateNow = [bool]($u -is [bool] -and $u) -or [bool]("$u" -match '^(?i)(true|1)$')
    $v = "$(Get-PimUpdateNowField $b 'version')".Trim()
    if ($v -match '^\d+(\.\d+){1,5}$') { $res.version = $v }
    $res.raisedAt = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $b 'raisedAt')
    $sc = "$(Get-PimUpdateNowField $b 'scope')".Trim().ToLowerInvariant()
    $res.scope = $(if ($sc -in @('ring', 'environment')) { $sc } else { 'ring' })
    $by = ("$(Get-PimUpdateNowField $b 'by')" -replace '\s+', ' ').Trim(); if ($by.Length -gt 80) { $by = $by.Substring(0, 80) }
    $res.by = $by
    # UPDATE-NOW-HEAD: a STORED record of a /head expedite carries its source + apply / until / sequence / key
    $res.source = 'signal'; $res.apply = ''; $res.until = $null; $res.sequence = 0; $res.key = ''
    if ("$(Get-PimUpdateNowField $b 'source')".Trim() -eq 'head') {
        $res.source = 'head'
        $ap = "$(Get-PimUpdateNowField $b 'apply')".Trim().ToLowerInvariant(); if ($ap -in @('now', 'window')) { $res.apply = $ap }
        $res.until = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $b 'until')
        $sq = [int64]0; if ([int64]::TryParse("$(Get-PimUpdateNowField $b 'sequence')".Trim(), [ref]$sq) -and $sq -gt 0) { $res.sequence = $sq }
        $res.key = "$(Get-PimUpdateNowField $b 'key')".Trim()
    }
    return $res
}

function ConvertTo-PimUpdateNowSignalRecord {
    # PURE. A parsed signal as the object kept in the state (no 'by': a name stays out of the store and the heartbeat).
    # A /head expedite (source 'head') also keeps apply / until / sequence / key -- never the expedite's reason text.
    param([AllowNull()][hashtable]$Signal)
    if ($null -eq $Signal) { return $null }
    $o = [ordered]@{ updateNow = [bool]$Signal.updateNow; version = "$($Signal.version)"
                     raisedAt = $(if ($Signal.raisedAt) { ([datetime]$Signal.raisedAt).ToString('o') } else { '' }); scope = "$($Signal.scope)" }
    if ("$($Signal.source)" -eq 'head') {
        $o['source'] = 'head'; $o['apply'] = "$($Signal.apply)"
        $o['until'] = $(if ($Signal.until) { ([datetime]$Signal.until).ToString('o') } else { '' })
        $o['sequence'] = [int64]$(if ($Signal.sequence) { $Signal.sequence } else { 0 }); $o['key'] = "$($Signal.key)"
    }
    return [pscustomobject]$o
}

function ConvertFrom-PimUpdateNowHead {
    <#
      PURE. The POST /head 200 body -> @{ ok; version; sequence; wave; apply (now|window|''); until (UTC or $null); reason }.
      version null / not a release version = ''. An expedite whose apply is neither 'now' nor 'window' is no expedite.
    #>
    param([AllowNull()][object]$Body)
    $b = ConvertFrom-PimUpdateNowStored $Body
    $res = @{ ok = $false; version = ''; sequence = [int64]0; wave = ''; apply = ''; until = $null; reason = '' }
    if ($null -eq $b -or $b -is [string] -or $b -is [ValueType]) { return $res }
    $res.ok = $true
    $v = "$(Get-PimUpdateNowField $b 'version')".Trim(); if ($v -match '^\d+(\.\d+){1,5}$') { $res.version = $v }
    $sq = [int64]0; if ([int64]::TryParse("$(Get-PimUpdateNowField $b 'sequence')".Trim(), [ref]$sq) -and $sq -gt 0) { $res.sequence = $sq }
    $w = "$(Get-PimUpdateNowField $b 'wave')".Trim(); if ($w -match '^[A-Za-z0-9._-]{1,40}$') { $res.wave = $w }
    $x = Get-PimUpdateNowField $b 'expedite'
    if ($null -ne $x -and -not ($x -is [string]) -and -not ($x -is [ValueType])) {
        $ap = "$(Get-PimUpdateNowField $x 'apply')".Trim().ToLowerInvariant()
        if ($ap -in @('now', 'window')) { $res.apply = $ap }
        $res.until = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $x 'until')
        $r = ("$(Get-PimUpdateNowField $x 'reason')" -replace '\s+', ' ').Trim(); if ($r.Length -gt 120) { $r = $r.Substring(0, 120) }
        $res.reason = $r
    }
    return $res
}

function ConvertTo-PimUpdateNowHeadSignal {
    <#
      PURE. A parsed /head answer as the quick check's signal (the shape ConvertFrom-PimUpdateNowSignal returns, source
      'head'). updateNow = an expedite (now|window) for a named version. raisedAt = the first time THIS updater saw this
      expedite (key = version#sequence#apply): taken from -Previous (the stored signal) when the key is the same, else
      -NowUtc -- so "at most once per raisedAt" holds for /head too, and an unchanged answer writes nothing.
    #>
    param([Parameter(Mandatory)][hashtable]$Head, [AllowNull()][object]$Previous, [datetime]$NowUtc = [datetime]::UtcNow)
    $upd = [bool]($Head.apply -and $Head.version)
    $key = $(if ($upd) { "$($Head.version)#$($Head.sequence)#$($Head.apply)" } else { '' })
    $raised = $null
    if ($upd) {
        $pp = $null; if ($null -ne $Previous) { $pp = ConvertFrom-PimUpdateNowSignal -Body $Previous }
        if ($pp -and $pp.ok -and $pp.source -eq 'head' -and $pp.key -eq $key -and $null -ne $pp.raisedAt) { $raised = $pp.raisedAt }
        else { $n = $NowUtc.ToUniversalTime(); $raised = New-Object datetime ($n.Year, $n.Month, $n.Day, $n.Hour, $n.Minute, $n.Second, [DateTimeKind]::Utc) }
    }
    return @{ ok = $true; updateNow = $upd; version = "$($Head.version)"; raisedAt = $raised; scope = 'ring'; by = ''
              source = 'head'; apply = $(if ($upd) { "$($Head.apply)" } else { '' }); until = $(if ($upd) { $Head.until } else { $null })
              sequence = [int64]$Head.sequence; key = $key }
}

function Get-PimUpdateNowRefusalLine {
    <#
      PURE. The ONE line for a refused /head (401 / 403 / 422). The code comes from the answer's 'error' (else a one-word
      'reason'); a 403 licence is said as a licence refusal -- never as "no route". Never echoes the key or the licence.
    #>
    param([int]$Status, [AllowNull()][object]$Body)
    $b = ConvertFrom-PimUpdateNowStored $Body
    $code = ''
    foreach ($f in 'error', 'code', 'reason') {
        $c = "$(Get-PimUpdateNowField $b $f)".Trim()
        if ($c -match '^[A-Za-z][A-Za-z0-9_.-]{0,39}$') { $code = $c; break }
    }
    $tail = '-- nothing checked; the nightly run reports it'
    switch ($Status) {
        401 { return "update now: Invardia refused the install key (401) $tail" }
        403 {
            switch -Regex ($code) {
                '^(?i)licen[cs]e' { return "update now: Invardia refused the licence (403 licence) $tail" }
                '^(?i)installKeyBound$' { return "update now: Invardia refused the install key as bound to another install (403 installKeyBound) $tail" }
                '^(?i)ring$' { return "update now: Invardia refused this environment's ring (403 ring) $tail" }
            }
            if ($code) { return "update now: Invardia refused the quick check (403 $code) $tail" }
            return "update now: Invardia refused the quick check (403: the licence, the install key's binding or the ring) $tail"
        }
        422 { return "update now: Invardia refused the quick check as invalid (422$(if ($code) { " $code" })) $tail" }
    }
    return "update now: Invardia answered HTTP $Status $tail"
}

function Invoke-PimUpdateNowQuickCheck {
    <#
      The quick execution's whole check, every seam injected. Never throws. Returns @{ run; line; signal; stateSaved }:
        run = $true  -> the caller runs the normal update in this execution (after Get-PimUpdateNowApprovalDecision and
                        Set-PimUpdateNowHandled); signal = the parsed signal
        run = $false -> the caller says -line and exits 0
      Gates, in order (the cheap ones first; the network only when it can matter):
        off for this ring -> no install key (community / Invardia-less: NO call) -> no ring -> the signal (404 / 0 / 5xx =
        no signal, quietly; 304 = the stored one) -> updateNow false -> older than 24 h -> already acted on (raisedAt) ->
        not newer than the installed version -> PIM_UPDATE_HOLD -> another updater execution running (guard Strict mode is
        NEVER a gate: owner 2026-11-09 "strict mode can never block an update")
        (unreadable = not started).
      Seams: -Head { } -> @{ status; body; error }  (UPDATE-NOW-HEAD: POST /head; the seam holds the key + licence, this
                                                       function never sees the licence)
             -Signal { param($ETag) } -> @{ status; body; etag }   (the old GET /signal: only when -Head is not given, or
                                                       /head answered 404 -- an older Invardia; once per run)
             -GetState { } -> the stored state   -SetState { param($o) }   -IsRunning { } -> $true | $false | $null
      -UpdateWindow (PIM_UPDATE_WINDOW) / -NightlyUtc: the window an apply='window' expedite waits for (Get-PimUpdateWindowState).
      No retry inside one execution: the next 15-minute slot is the retry.
    #>
    param([bool]$Enabled = $false, [AllowEmptyString()][string]$InstallKey = '', [AllowEmptyString()][string]$Ring = '',
          [AllowEmptyString()][string]$RunningVersion = '', [bool]$Hold = $false, [bool]$StrictActive = $false, [AllowEmptyString()][string]$StrictUntil = '',
          [scriptblock]$Head, [scriptblock]$Signal, [scriptblock]$GetState, [scriptblock]$SetState, [scriptblock]$IsRunning,
          [AllowEmptyString()][string]$UpdateWindow = '', [AllowEmptyString()][string]$NightlyUtc = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $res = @{ run = $false; line = ''; signal = $null; stateSaved = $false; source = '' }
    try {
        $now = $NowUtc.ToUniversalTime()
        $ringN = -1; [void][int]::TryParse("$Ring".Trim(), [ref]$ringN)
        if (-not $Enabled) { $res.line = "update now: off for ring $("$Ring".Trim()) (PIM_UPDATE_NOW) -- nothing checked"; return $res }
        if (-not "$InstallKey".Trim()) { $res.line = 'update now: this install has no install key -- no signal is asked for'; return $res }
        if ($ringN -lt 0 -or $ringN -gt 3) { $res.line = "update now: this environment has no update ring ('$Ring') -- nothing checked"; return $res }

        $st = $null; if ($GetState) { try { $st = ConvertFrom-PimUpdateNowStored (& $GetState) } catch { $st = $null } }
        $prevEtag = "$(Get-PimUpdateNowField $st 'etag')"
        $prevSig = Get-PimUpdateNowField $st 'signal'
        $newEtag = $prevEtag; $sig = $null; $sigNote = ''

        $save = {
            param($line)
            $res.line = $line
            # the stored signal NORMALISED the same way (PowerShell 7's ConvertFrom-Json turns raisedAt into a [datetime],
            # which serialises differently -- compared raw, every unchanged check would write the store again)
            $prevNorm = $(if ($null -ne $prevSig) { $pp = ConvertFrom-PimUpdateNowSignal -Body $prevSig; if ($pp.ok) { ConvertTo-PimUpdateNowSignalRecord -Signal $pp } else { $prevSig } } else { $null })
            $o = [ordered]@{ etag = $newEtag; signal = $(if ($null -ne $sig) { ConvertTo-PimUpdateNowSignalRecord -Signal $sig } else { $prevNorm })
                             handledRaisedAt = (ConvertTo-PimUpdateNowIso (Get-PimUpdateNowField $st 'handledRaisedAt')); handledVersion = "$(Get-PimUpdateNowField $st 'handledVersion')"
                             startedUtc = (ConvertTo-PimUpdateNowIso (Get-PimUpdateNowField $st 'startedUtc')); lastResult = "$line"; changedUtc = $now.ToString('o') }
            $a = ConvertTo-Json -InputObject ([ordered]@{ e = $o.etag; s = $o.signal; r = $o.lastResult }) -Depth 4 -Compress
            $b = ConvertTo-Json -InputObject ([ordered]@{ e = $prevEtag; s = $prevNorm; r = "$(Get-PimUpdateNowField $st 'lastResult')" }) -Depth 4 -Compress
            if ($a -ne $b -and $SetState) { try { & $SetState ([pscustomobject]$o); $res.stateSaved = $true } catch { } }
        }

        # ---- UPDATE-NOW-HEAD: POST /head first; only a 404 (an older Invardia) falls back to GET /signal, once ----------
        $useSignal = (-not $Head)
        if ($Head) {
            $hAns = $null; try { $hAns = & $Head } catch { $hAns = $null }
            $hCode = 0; try { $hCode = [int](Get-PimUpdateNowField $hAns 'status') } catch { $hCode = 0 }
            if ($hCode -eq 404) { $useSignal = $true; $res.source = 'signal-fallback' }
            else {
                $res.source = 'head'
                if ($hCode -eq 200 -or $hCode -eq 204) {
                    $hp = $(if ($hCode -eq 200) { ConvertFrom-PimUpdateNowHead -Body (Get-PimUpdateNowField $hAns 'body') } else { @{ ok = $true; version = ''; sequence = [int64]0; wave = ''; apply = ''; until = $null; reason = '' } })
                    if ($hp.ok) { $sig = ConvertTo-PimUpdateNowHeadSignal -Head $hp -Previous $prevSig -NowUtc $now }
                    else { $sigNote = 'the quick-check answer could not be read' }
                } elseif ($hCode -in @(401, 403, 422)) {
                    & $save (Get-PimUpdateNowRefusalLine -Status $hCode -Body (Get-PimUpdateNowField $hAns 'body')); return $res
                } else {
                    $hErr = "$(Get-PimUpdateNowField $hAns 'error')".Trim()
                    $sigNote = $(if ($hCode -eq 0 -and $hErr -eq 'no licence') { 'no licence in the store -- the quick check needs it, so it was not asked' }
                                 elseif ($hCode -eq 0) { 'Invardia could not be reached' }
                                 elseif ($hCode -eq 429) { 'Invardia asked to wait (429)' }
                                 else { "Invardia answered HTTP $hCode" })
                }
            }
        }
        if ($useSignal) {
            if (-not $res.source) { $res.source = 'signal' }
            $ans = $null; try { if ($Signal) { $ans = & $Signal $prevEtag } } catch { $ans = $null }
            $code = 0; try { $code = [int](Get-PimUpdateNowField $ans 'status') } catch { $code = 0 }
            if ($code -eq 200) {
                $p = ConvertFrom-PimUpdateNowSignal -Body (Get-PimUpdateNowField $ans 'body')
                if ($p.ok) { $sig = $p; $newEtag = "$(Get-PimUpdateNowField $ans 'etag')".Trim() } else { $sigNote = 'the signal answer could not be read' }
            } elseif ($code -eq 304) {
                if ($null -ne $prevSig) { $sig = ConvertFrom-PimUpdateNowSignal -Body $prevSig }
                else { $sigNote = 'unchanged (304) and nothing stored' }
            } elseif ($code -eq 204) { $sig = @{ ok = $true; updateNow = $false; version = ''; raisedAt = $null; scope = ''; by = '' }; $newEtag = '' }
            else { $sigNote = $(if ($code -eq 404) { 'Invardia has no signal route yet (404)' } elseif ($code -eq 0) { 'Invardia could not be reached' } else { "Invardia answered HTTP $code" }) }
        }
        $isHead = [bool]($null -ne $sig -and "$($sig.source)" -eq 'head')

        if ($null -eq $sig) { & $save "update now: no signal ($sigNote) -- nothing to do"; return $res }
        $res.signal = $sig
        if (-not $sig.updateNow) {
            if ($isHead) {
                $hv = "$($sig.version)"
                & $save $(if ($hv) { "update now: Invardia's head for ring $ringN is $hv with no expedite -- nothing to do (the nightly run covers it)" } else { "update now: Invardia's head for ring $ringN names no version -- nothing to do" })
            } else { & $save 'update now: no update-now signal for this environment -- nothing to do' }
            return $res
        }
        $raised = $sig.raisedAt
        if ($null -eq $raised) { & $save 'update now: a signal without raisedAt -- ignored'; return $res }
        if (($now - $raised).TotalHours -ge (Get-PimUpdateNowMaxAgeHours)) { & $save ("update now: the signal raised {0:u} is older than 24 h -- ignored (the nightly run takes it)" -f $raised); return $res }
        if ($isHead -and $null -ne $sig.until -and $now -ge $sig.until) {
            & $save ("update now: the expedite ($($sig.apply)) for $($sig.version) ran out at {0:u} -- nothing to do (the nightly run covers it)" -f $sig.until); return $res
        }
        $handled = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $st 'handledRaisedAt')
        if ($null -ne $handled -and $handled -eq $raised) {
            & $save ("update now: this signal (raised {0:u}) was acted on at {1} -- not again (a failed update is retried by the nightly run)" -f $raised, "$(Get-PimUpdateNowField $st 'startedUtc')"); return $res
        }
        $who = $(if ($isHead) { "ring $ringN (expedite $($sig.apply))" } elseif ($sig.scope -eq 'environment') { 'this environment' } else { "ring $ringN" })
        $cmp = Compare-PimUpdateNowVersion -A $sig.version -B $RunningVersion
        if ($null -eq $cmp) { & $save "update now: signal for $who, but the version ('$($sig.version)') or the installed version ('$RunningVersion') cannot be read -- not started"; return $res }
        if ($cmp -le 0) { & $save "update now: signal for $who names $($sig.version); this environment already runs $RunningVersion -- nothing to do"; return $res }
        if ($isHead -and $sig.apply -eq 'window') {
            $ws = Get-PimUpdateWindowState -Window $UpdateWindow -NightlyUtc $NightlyUtc -NowUtc $now
            $wn = $(if ($ws.note) { " ($($ws.note))" } else { '' })
            if (-not $ws.open) {
                & $save ("update now: signal for $who names $($sig.version), but {0:HH:mm} UTC is outside this install's update window $($ws.text) UTC ($($ws.source))$wn -- not started (checked again next slot)" -f $now); return $res
            }
        }
        if ($Hold) { & $save "update now: signal for $who ($($sig.version)), but this environment is HELD (PIM_UPDATE_HOLD=1) -- not started"; return $res }
        # OWNER 2026-11-09: "we have no guards anywhere that blocks updates. strict mode lowers guards in the solution" --
        # -StrictActive is accepted for older callers and IGNORED: guard Strict mode never holds an update.
        $running = $null; if ($IsRunning) { try { $running = & $IsRunning } catch { $running = $null } }
        if ($running -is [bool] -and $running) { & $save "update now: signal for $who ($($sig.version)), but another updater execution is running -- not started"; return $res }
        if (-not ($running -is [bool])) { & $save "update now: signal for $who ($($sig.version)), but the updater's executions could not be read -- not started"; return $res }
        $res.run = $true
        & $save ("update now: signal for $who (raised {0:u}) names $($sig.version), installed $RunningVersion -- checking the ring's approval" -f $raised)
        return $res
    } catch {
        $res.run = $false; $res.line = "update now: the check failed quietly ($((("$($_.Exception.Message)") -split "`n")[0])) -- nothing started"
        return $res
    }
}

function Get-PimUpdateNowApprovalDecision {
    <#
      PURE. The ring stays the authority: the signal says NOW, never WHICH version. @{ ok; line }:
        the ring approves nothing / an unreadable version  -> not ok
        the ring approves a version OLDER than the signal's -> not ok (not approved for this ring yet)
        the ring's version is not newer than the installed  -> not ok
        else ok (the update runs; it installs what the RING approves)
    #>
    param([AllowEmptyString()][string]$SignalVersion = '', [AllowEmptyString()][string]$ApprovedVersion = '', [AllowEmptyString()][string]$RunningVersion = '', [AllowEmptyString()][string]$Ring = '')
    $a = "$ApprovedVersion".Trim()
    if (-not $a) { return @{ ok = $false; line = "update now: ring $Ring approves no version -- the signal's $SignalVersion is not approved for this ring; nothing started" } }
    $c1 = Compare-PimUpdateNowVersion -A $a -B $SignalVersion
    if ($null -eq $c1) { return @{ ok = $false; line = "update now: the ring's version ('$a') or the signal's ('$SignalVersion') cannot be read -- nothing started" } }
    if ($c1 -lt 0) { return @{ ok = $false; line = "update now: ring $Ring approves $a, older than the signal's $SignalVersion -- not approved for this ring yet; nothing started" } }
    $c2 = Compare-PimUpdateNowVersion -A $a -B $RunningVersion
    if ($null -ne $c2 -and $c2 -le 0) { return @{ ok = $false; line = "update now: ring $Ring approves $a and this environment runs $RunningVersion -- nothing to do" } }
    return @{ ok = $true; line = "update now: ring $Ring approves $a -- updating now" }
}

function Set-PimUpdateNowHandled {
    <#
      Mark the signal as acted on BEFORE the update starts (at most ONE update per raisedAt, whatever happens next).
      Returns $true when the mark was stored; $false = the caller must NOT start (it could not promise "once").
    #>
    param([scriptblock]$GetState, [Parameter(Mandatory)][scriptblock]$SetState, [AllowNull()][hashtable]$Signal, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        if ($null -eq $Signal -or $null -eq $Signal.raisedAt) { return $false }
        $st = $null; if ($GetState) { try { $st = ConvertFrom-PimUpdateNowStored (& $GetState) } catch { $st = $null } }
        $o = [ordered]@{ etag = "$(Get-PimUpdateNowField $st 'etag')"; signal = (ConvertTo-PimUpdateNowSignalRecord -Signal $Signal)
                         handledRaisedAt = ([datetime]$Signal.raisedAt).ToString('o'); handledVersion = "$($Signal.version)"; startedUtc = $NowUtc.ToUniversalTime().ToString('o')
                         lastResult = "update now: the update started for the signal raised $(([datetime]$Signal.raisedAt).ToString('u'))"; changedUtc = $NowUtc.ToUniversalTime().ToString('o') }
        & $SetState ([pscustomobject]$o)
        return $true
    } catch { return $false }
}

function New-PimUpdateNowPendingFields {
    <#
      PURE. The three UpdatePending fields (ON by default; PIM_UPLINK_UPDATENOWFIELDS=0 switches them off):
        signal      'none' | 'ring' | 'environment'  -- an update-now signal that is set and younger than 24 h, by its scope
        raisedAt    when it was raised (ISO UTC), or $null
        startedUtc  when the updater started the update for THAT signal (ISO UTC), or $null
      No name, no version text, no reason -- closed values and times only.
    #>
    param([AllowNull()][object]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = ConvertFrom-PimUpdateNowStored $State
    $out = [ordered]@{ signal = 'none'; raisedAt = $null; startedUtc = $null }
    if ($null -eq $st) { return $out }
    $sg = Get-PimUpdateNowField $st 'signal'
    if ($null -eq $sg) { return $out }
    $p = ConvertFrom-PimUpdateNowSignal -Body $sg
    if (-not $p.ok -or -not $p.updateNow -or $null -eq $p.raisedAt) { return $out }
    if (($NowUtc.ToUniversalTime() - $p.raisedAt).TotalHours -ge (Get-PimUpdateNowMaxAgeHours)) { return $out }
    $out.signal = $p.scope
    $out.raisedAt = $p.raisedAt.ToString('o')
    $h = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $st 'handledRaisedAt')
    $s = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $st 'startedUtc')
    if ($null -ne $h -and $h -eq $p.raisedAt -and $null -ne $s) { $out.startedUtc = $s.ToString('o') }
    return $out
}

function Invoke-PimUpdateNowSelfCronUpdate {
    <#
      The UPDATER's own job: its cron (and PIM_UPDATE_NIGHTLY_UTC) follow the UPDATE NOW switch -- Get-PimUpdateNowSelfCronPlan.
      This is how an EXISTING install gets the 15-minute cron: its next full run (the nightly one) writes it, with the right
      the updater already holds (Contributor on its resource group -- the same right that stamps its own image and records
      PIM_UPDATE_LAST_BUILT on itself). No new role, no person (framework 12.23 P9).
      ONE PATCH: the configuration WITHOUT secrets (a GET returns them without values; sending them back would blank them),
      the schedule's cron replaced, the template as read with PIM_UPDATE_NIGHTLY_UTC set; busy is waited out
      (Invoke-PimArmBusyRetry), then the cron is READ BACK. Never throws. Returns @{ ok; changed; action; detail }.
      -Arm { param($Method, $Path, $Body) }   (the path carries its api-version)
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$JobName,
          [Parameter(Mandatory)][scriptblock]$Arm, [bool]$Enabled = $false, [string]$ApiVersion = '2024-03-01',
          [int[]]$BusyWaits = @(20, 20, 20), [scriptblock]$Sleep)
    $res = @{ ok = $true; changed = $false; action = 'none'; detail = '' }
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName`?api-version=$ApiVersion"
    $envOf = { param($jo, $n)
        foreach ($c in @($jo.properties.template.containers)) { foreach ($v in @($c.env)) { if ($v -and "$($v.name)" -eq $n) { return "$($v.value)" } } }
        return '' }
    try {
        $j = & $Arm 'GET' $path $null
        if (-not $j) { $res.ok = $false; $res.detail = "update now: the updater's own job '$JobName' could not be read -- its cron is left as it is"; return $res }
        $cur = "$($j.properties.configuration.scheduleTriggerConfig.cronExpression)"
        $plan = Get-PimUpdateNowSelfCronPlan -CurrentCron $cur -NightlyUtc (& $envOf $j 'PIM_UPDATE_NIGHTLY_UTC') -Enabled $Enabled
        $res.action = $plan.action
        if ($plan.action -eq 'none') { $res.detail = "update now: cron '$cur' -- $($plan.reason)"; return $res }
        $want = "$($plan.cron)"; $nightly = "$($plan.nightlyUtc)"
        [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write {
            $jw = & $Arm 'GET' $path $null
            if (-not $jw) { throw "job '$JobName' not found" }
            $cfg = [ordered]@{}
            foreach ($p in @($jw.properties.configuration.PSObject.Properties)) { if ($p.Name -ne 'secrets') { $cfg[$p.Name] = $p.Value } }
            $stc = [ordered]@{ cronExpression = $want; parallelism = 1; replicaCompletionCount = 1 }
            $old = $jw.properties.configuration.scheduleTriggerConfig
            if ($old) { foreach ($k in 'parallelism', 'replicaCompletionCount') { if ($old.PSObject.Properties[$k] -and $null -ne $old.$k) { $stc[$k] = $old.$k } } }
            $cfg['scheduleTriggerConfig'] = $stc
            $tpl = $jw.properties.template
            if ($nightly) {
                $cs = @($tpl.containers)
                $target = if ($cs.Count -eq 1) { $cs[0] } else { @($cs | Where-Object { "$($_.name)" -eq $JobName }) | Select-Object -First 1 }
                if ($target) {
                    $envList = New-Object System.Collections.Generic.List[object]
                    foreach ($v in @($target.env)) { if ($v -and "$($v.name)" -ne 'PIM_UPDATE_NIGHTLY_UTC') { $envList.Add($v) | Out-Null } }
                    $envList.Add([pscustomobject]@{ name = 'PIM_UPDATE_NIGHTLY_UTC'; value = $nightly }) | Out-Null
                    $target | Add-Member -NotePropertyName 'env' -NotePropertyValue @($envList.ToArray()) -Force
                }
            }
            & $Arm 'PATCH' $path @{ properties = @{ configuration = $cfg; template = $tpl } } })
        $back = & $Arm 'GET' $path $null
        $got = "$($back.properties.configuration.scheduleTriggerConfig.cronExpression)"
        if ($got -ne $want) { $res.ok = $false; $res.detail = "update now: wrote cron '$want' but read back '$got' -- the next full run tries again"; return $res }
        if ($nightly -and (& $envOf $back 'PIM_UPDATE_NIGHTLY_UTC') -ne $nightly) { $res.ok = $false; $res.detail = "update now: cron '$want' written, but PIM_UPDATE_NIGHTLY_UTC did not read back -- the next full run tries again"; return $res }
        $res.changed = $true
        $res.detail = "update now: the updater's cron '$cur' -> '$want' ($($plan.reason)); it takes effect from the next slot"
        return $res
    } catch {
        $m = (("$($_.Exception.Message)") -split "`n")[0]
        $res.ok = $false
        $res.detail = $(if ($m -match '(?i)OperationInProgress|active provisioning operation') { "update now: the updater's job is busy -- its cron is set on the next full run" } else { "update now: the updater's cron was not changed ($m) -- the next full run tries again" })
        return $res
    }
}
