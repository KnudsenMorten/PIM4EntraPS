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
  [!] SEC-PATCH-PIPELINE-1 pt 9 (Invardia 2026-11-27; framework SEC-LANE-1 G5 / IMAGE-30MIN-1): security is not something an
     operator opts out of. The 15-minute slot ALWAYS makes the cheap security check (the one POST /head; GET /signal only as
     the 404 fallback), whatever PIM_UPDATE_NOW says, and the updater's cron always keeps its quarter-hour slots
     (Get-PimUpdateNowSelfCronPlan). PIM_UPDATE_NOW=0 stops only FEATURE (code) updates in that slot: a newer image-only
     <build>.N of the running build is still applied at once; a code release waits for the nightly window, as before.
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

# ---- 3.1.72 review N2/C2 (2026-11-27): never widen the CODE cadence -------------------------------------------------------
# The quarter-hour cron carries the SECURITY check only. An install whose own nightly cron runs on certain DAYS (a weekly
# '0 3 * * 0', a monthly '0 3 1 * *') keeps that day pattern as the gate for CODE updates: it is kept on the job as
# PIM_UPDATE_NIGHTLY_DAYS ('<day-of-month> <month> <day-of-week>', '* * *' = every day = the setting is left off), and
# Get-PimUpdaterRunKind calls the nightly time of any other day a 'quick' (security-only) slot.
function Get-PimUpdateNowEveryDay { <# PURE. LITERAL. The day pattern of a daily cron. #> return '* * *' }

function ConvertTo-PimUpdateNowCronNumbers {
    <# PURE. FIXED 2026-11-27 (3.1.72 final review D2, for 3.1.73): one cron field with day / month NAMES as numbers --
       -Kind dow: SUN..SAT -> 0..6 ('MON-FRI' -> '1-5', 'SAT,SUN' -> '6,0'); -Kind month: JAN..DEC -> 1..12. Case-insensitive.
       A name that is not one of them is LEFT AS IT IS (the caller's check then calls the field unreadable -- fail safe). #>
    param([AllowNull()][AllowEmptyString()][string]$Field, [ValidateSet('dow', 'month')][string]$Kind)
    $names = $(if ($Kind -eq 'dow') { @('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT') } else { @('JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC') })
    $base = $(if ($Kind -eq 'dow') { 0 } else { 1 })
    $sb = New-Object System.Text.StringBuilder
    foreach ($tok in [regex]::Split("$Field", '([,\-/])')) {
        $i = [Array]::IndexOf($names, "$tok".ToUpperInvariant())
        if ($tok -match '^[A-Za-z]{3}$' -and $i -ge 0) { [void]$sb.Append("$($i + $base)") } else { [void]$sb.Append($tok) }
    }
    return $sb.ToString()
}

function ConvertFrom-PimUpdateNowDays {
    <# PURE. '<dom> <month> <dow>' -> @{ ok; text; every }. '' / $null = every day. A field must be * or digits , - / only.
       D2 (3.1.73): day-of-week names SUN..SAT and month names JAN..DEC (ranges, lists) are read as their numbers first, and
       text carries the NUMBERS ('* * SUN' -> '* * 0'). Anything else that is not readable = ok $false (the code gate stays shut). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ("$Text".Trim() -replace '\s+', ' ')
    if (-not $t) { return @{ ok = $true; text = (Get-PimUpdateNowEveryDay); every = $true } }
    $f = @($t -split ' ')
    if ($f.Count -eq 3) {
        $f = @($f[0], (ConvertTo-PimUpdateNowCronNumbers -Field $f[1] -Kind month), (ConvertTo-PimUpdateNowCronNumbers -Field $f[2] -Kind dow))
        $t = ($f -join ' ')
    }
    if ($f.Count -ne 3 -or @($f | Where-Object { $_ -notmatch '^(\*|\d{1,2}(-\d{1,2})?)(/\d{1,2})?(,(\*|\d{1,2}(-\d{1,2})?)(/\d{1,2})?)*$' }).Count) { return @{ ok = $false; text = $t; every = $false } }
    return @{ ok = $true; text = $t; every = ($t -eq (Get-PimUpdateNowEveryDay)) }
}

function Get-PimUpdateNowCodeDaysFact {
    <# PURE. FIXED 2026-11-27 (3.1.72 final review D3, for 3.1.73): the job's PIM_UPDATE_NIGHTLY_DAYS as a FACT, so an unreadable
       one is never only a run-log line. @{ state = ok | unreadable; days; line }. '' / '* * *' / a readable pattern = ok.
       unreadable = the install is security-only (no code update ever): the updater counts it "to fix by hand", records it for the
       heartbeat (UpdateState.setupFacts.updaterCodeDays -> the setup control 'updater-schedule' = wrong / disabled) and the
       15-minute check's one line says it. #>
    param([AllowNull()][AllowEmptyString()][string]$Days)
    $raw = "$Days".Trim()
    $d = ConvertFrom-PimUpdateNowDays -Text $raw
    if ($d.ok) { return @{ state = 'ok'; days = $d.text; line = '' } }
    return @{ state = 'unreadable'; days = $raw
              line = "PIM_UPDATE_NIGHTLY_DAYS '$raw' cannot be read -- CODE updates are CLOSED here (security check only); re-run Deploy-PimUpdateJob with a readable -Cron (fix by hand)" }
}

function Resolve-PimUpdateJobSetupCron {
    <# PURE. FIXED 2026-11-27 (3.1.72 final review F3, for 3.1.73): the NIGHTLY cron a setup re-run works with.
         -Cron / -CronGiven   the -Cron parameter and whether it was passed      -ExistingCron  the job's cronExpression now
         -ExistingNightlyUtc / -ExistingNightlyDays   PIM_UPDATE_NIGHTLY_UTC / PIM_UPDATE_NIGHTLY_DAYS on the job now
       -Cron passed = that cron. NOT passed = the job's existing DAY pattern is kept (SUPERSEDED: the default '0 3 * * *' replaced
       it and dropped PIM_UPDATE_NIGHTLY_DAYS -- a weekly install became daily for code on a plain re-run):
         the job still on a one-time-a-day-pattern cron (e.g. '0 3 * * 0')            -> that cron
         PIM_UPDATE_NIGHTLY_UTC + a non-daily readable PIM_UPDATE_NIGHTLY_DAYS       -> 'M H <days>' at that time
         PIM_UPDATE_NIGHTLY_UTC + an UNREADABLE PIM_UPDATE_NIGHTLY_DAYS              -> 'M H * * *' + keepDaysRaw = the value
                                                                                       (written back as it is: the gate stays shut)
         anything else (a new job, a daily one)                                       -> -Cron (the default), as before
       @{ cron; keepDaysRaw; reason }. #>
    param([AllowNull()][AllowEmptyString()][string]$Cron, [bool]$CronGiven, [AllowNull()][AllowEmptyString()][string]$ExistingCron = '',
          [AllowNull()][AllowEmptyString()][string]$ExistingNightlyUtc = '', [AllowNull()][AllowEmptyString()][string]$ExistingNightlyDays = '')
    $def = @{ cron = "$Cron"; keepDaysRaw = ''; reason = '' }
    if ($CronGiven) { $def.reason = "-Cron '$Cron' as given"; return $def }
    $every = Get-PimUpdateNowEveryDay
    $ec = Get-PimUpdateNowCronPlan -NightlyCron $ExistingCron
    if ($ec.ok -and "$($ec.nightlyDays)" -ne $every) { return @{ cron = "$($ec.nightlyCron)"; keepDaysRaw = ''; reason = "kept the job's own cron '$($ec.nightlyCron)' (no -Cron given)" } }
    $n = ConvertFrom-PimUpdateNowNightly -Text $ExistingNightlyUtc
    $raw = "$ExistingNightlyDays".Trim()
    if ($n.ok -and $raw) {
        $d = ConvertFrom-PimUpdateNowDays -Text $raw
        if ($d.ok -and -not $d.every) { $c = ('{0} {1} {2}' -f $n.minute, $n.hour, $d.text); return @{ cron = $c; keepDaysRaw = ''; reason = "kept the job's day pattern '$($d.text)' at $($n.text) UTC (no -Cron given)" } }
        if (-not $d.ok) { return @{ cron = ('{0} {1} * * *' -f $n.minute, $n.hour); keepDaysRaw = $raw; reason = "kept the job's PIM_UPDATE_NIGHTLY_DAYS '$raw' as it is (unreadable: CODE updates stay closed -- give -Cron to fix it)" } }
    }
    $def.reason = "-Cron '$Cron' (the default; the job had no day pattern to keep)"
    return $def
}

function Test-PimUpdateNowCronField {
    <# PURE. Does -Value match ONE cron field (*, n, a-b, */s, a-b/s, lists)? #>
    param([string]$Field, [int]$Value, [int]$Min, [int]$Max)
    foreach ($part in @("$Field" -split ',')) {
        $step = 1; $rng = $part
        if ($part -match '^(.+)/(\d{1,2})$') { $rng = $Matches[1]; $step = [Math]::Max(1, [int]$Matches[2]) }
        $lo = $Min; $hi = $Max
        if ($rng -eq '*') { }
        elseif ($rng -match '^(\d{1,2})-(\d{1,2})$') { $lo = [int]$Matches[1]; $hi = [int]$Matches[2] }
        elseif ($rng -match '^\d{1,2}$') { $lo = [int]$rng; $hi = $(if ($part -match '/') { $Max } else { [int]$rng }) }
        else { continue }
        if ($Value -ge $lo -and $Value -le $hi -and (($Value - $lo) % $step) -eq 0) { return $true }
    }
    return $false
}

function Test-PimUpdateNowDayMatch {
    <# PURE. Is -DateUtc a nightly day of -Days ('<dom> <month> <dow>')? Cron rule: when BOTH day-of-month and day-of-week
       are restricted, either one matching is enough. Unreadable days = $false (fail safe: no code update outside the day). #>
    param([AllowNull()][AllowEmptyString()][string]$Days, [Parameter(Mandatory)][datetime]$DateUtc)
    $d = ConvertFrom-PimUpdateNowDays -Text $Days
    if (-not $d.ok) { return $false }
    if ($d.every) { return $true }
    $f = @($d.text -split ' ')
    $u = $DateUtc.ToUniversalTime()
    if (-not (Test-PimUpdateNowCronField -Field $f[1] -Value $u.Month -Min 1 -Max 12)) { return $false }
    $dow = [int]$u.DayOfWeek
    $domOk = Test-PimUpdateNowCronField -Field $f[0] -Value $u.Day -Min 1 -Max 31
    $dowOk = (Test-PimUpdateNowCronField -Field $f[2] -Value $dow -Min 0 -Max 7) -or ($dow -eq 0 -and (Test-PimUpdateNowCronField -Field $f[2] -Value 7 -Min 0 -Max 7))
    if ($f[0] -ne '*' -and $f[2] -ne '*') { return [bool]($domOk -or $dowOk) }
    return [bool]($domOk -and $dowOk)
}

function Get-PimUpdateNowCronPlan {
    <#
      PURE. A nightly cron ('M H * * *', the only shape the updater has ever been deployed with) -> @{ ok; nightlyUtc
      ('HH:mm'); quarterCron; nightlyCron; nightlyDays; reason }. Any other shape -> ok = $false: the job keeps that cron, every
      execution a full run, and UPDATE NOW cannot be used there (said in reason).
      3.1.72 review N2/C2: a cron at ONE time on certain days ('M H <dom> <month> <dow>', e.g. weekly '0 3 * * 0') is ok too:
      nightlyDays = '<dom> <month> <dow>' (the CODE gate, kept on the job as PIM_UPDATE_NIGHTLY_DAYS); a daily cron = '* * *'.
    #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyCron)
    $c = ("$NightlyCron".Trim() -replace '\s+', ' ')
    $res = @{ ok = $false; nightlyUtc = ''; quarterCron = ''; nightlyCron = $c; nightlyDays = (Get-PimUpdateNowEveryDay); reason = '' }
    if ($c -notmatch '^(\d{1,2}) (\d{1,2}) (\S+) (\S+) (\S+)$') { $res.reason = "the updater's cron '$c' is not a daily 'M H * * *' -- it is kept, and UPDATE NOW needs a daily one"; return $res }
    $m = [int]$Matches[1]; $h = [int]$Matches[2]; $days = "$($Matches[3]) $($Matches[4]) $($Matches[5])"
    if ($m -gt 59 -or $h -gt 23) { $res.reason = "the updater's cron '$c' is not a valid time"; return $res }
    $dd = ConvertFrom-PimUpdateNowDays -Text $days
    if (-not $dd.ok) { $res.reason = "the updater's cron '$c' has a day pattern ('$days') this updater cannot read -- it is kept, and UPDATE NOW needs a daily one"; return $res }
    $res.ok = $true; $res.nightlyUtc = ('{0:D2}:{1:D2}' -f $h, $m); $res.quarterCron = Get-PimUpdateNowQuarterCron -Minute $m
    $res.nightlyDays = $dd.text
    $res.nightlyCron = ('{0} {1} {2}' -f $m, $h, $dd.text)
    $res.reason = $(if ($dd.every) { "nightly at $($res.nightlyUtc) UTC; every 15 minutes = '$($res.quarterCron)'" }
                    else { "code updates only at $($res.nightlyUtc) UTC on the days '$($dd.text)' (the install's own cron, kept as PIM_UPDATE_NIGHTLY_DAYS); every 15 minutes = '$($res.quarterCron)' for the security check" })
    return $res
}

function Get-PimUpdateNowSelfCronPlan {
    <#
      PURE. What the UPDATER does with ITS OWN job's cron on a full run (an existing install converges here; it already holds
      Contributor on its resource group -- the right that rolls the Manager and stamps its own image).
        -CurrentCron   the job's cronExpression now          -NightlyUtc  PIM_UPDATE_NIGHTLY_UTC on the job ('' = none)
        -Enabled       Test-PimUpdateNowEnabled for this environment
      Returns @{ action = none|quarter; cron; nightlyUtc; reason }:
        quarter  the job is on a daily cron                 -> cron = the 15-minute cron, nightlyUtc = that daily time
                 a 15-minute cron off the nightly minute    -> corrected to the nightly minute's quarter-hours
                 any other cron, nightly time readable      -> the 15-minute cron on PIM_UPDATE_NIGHTLY_UTC's minute
                 any other cron, no nightly time            -> the 15-minute cron on setup's default nightly 03:00
        none     already right, or a 15-minute cron with no nightly time (it cannot tell the nightly slot; said in reason)
      SEC-PATCH-PIPELINE-1 pt 9 (Invardia 2026-11-27; framework SEC-LANE-1 G5 / IMAGE-30MIN-1): -Enabled (PIM_UPDATE_NOW) no
      longer changes the cron -- the quarter-hour slot carries the security check, and security is not something an
      operator opts out of. (Was: OFF on a 15-minute cron -> 'nightly', back to the daily cron.) -Enabled is kept for callers.
    #>
    # 3.1.72 review N2/C2: -NightlyDays = PIM_UPDATE_NIGHTLY_DAYS on the job; every result carries nightlyDays (the CODE gate,
    # '* * *' = every day). A cron at one time on certain days (weekly / monthly) keeps its day pattern there.
    param([AllowNull()][AllowEmptyString()][string]$CurrentCron, [AllowNull()][AllowEmptyString()][string]$NightlyUtc, [bool]$Enabled,
          [AllowNull()][AllowEmptyString()][string]$NightlyDays = '')
    $cur = ("$CurrentCron".Trim() -replace '\s+', ' ')
    $n = ConvertFrom-PimUpdateNowNightly -Text $NightlyUtc
    $keptDays = ConvertFrom-PimUpdateNowDays -Text $NightlyDays
    $kd = $(if ($keptDays.ok) { $keptDays.text } else { "$NightlyDays".Trim() })
    $daily = Get-PimUpdateNowCronPlan -NightlyCron $cur
    $isQuarter = [bool]($cur -match '^\d{1,2},\d{1,2},\d{1,2},\d{1,2} \* \* \* \*$')
    if ($daily.ok) { return @{ action = 'quarter'; cron = $daily.quarterCron; nightlyUtc = $daily.nightlyUtc; nightlyDays = $daily.nightlyDays; reason = "the updater checks every 15 minutes -- the security check always, feature updates when UPDATE NOW is on ($($daily.reason))" } }
    # FIXED 2026-11-27 (3.1.72 final review D2, for 3.1.73): a cron at ONE time whose day part this updater still cannot read
    # (not '* * *', not a number / name pattern) keeps the CODE gate CLOSED: nightlyDays = that day part as written (unreadable ->
    # Test-PimUpdateNowDayMatch says no day, ever) -- never the daily fall-back below, which WIDENED code updates to every night.
    # The security check still gets its quarter-hour slots. SUPERSEDED: such a cron fell through to "nightlyDays = $kd" (''
    # on a job without PIM_UPDATE_NIGHTLY_DAYS = every day).
    if ($cur -match '^(\d{1,2}) (\d{1,2}) (\S+) (\S+) (\S+)$' -and [int]$Matches[1] -le 59 -and [int]$Matches[2] -le 23) {
        $um = [int]$Matches[1]; $uh = [int]$Matches[2]; $ud = "$($Matches[3]) $($Matches[4]) $($Matches[5])"
        if ($ud -ne (Get-PimUpdateNowEveryDay) -and -not (ConvertFrom-PimUpdateNowDays -Text $ud).ok) {
            return @{ action = 'quarter'; cron = (Get-PimUpdateNowQuarterCron -Minute $um); nightlyUtc = ('{0:D2}:{1:D2}' -f $uh, $um); nightlyDays = $ud; codeGateClosed = $true
                      reason = "the updater's cron '$cur' has a day part ('$ud') this updater cannot read -- CODE updates stay CLOSED (security check only, every 15 minutes) until Deploy-PimUpdateJob is re-run with a readable -Cron (fix by hand)" }
        }
    }
    if ($isQuarter -and $n.ok) {
        $want = Get-PimUpdateNowQuarterCron -Minute $n.minute
        # D2 (3.1.73): an unreadable kept day pattern is said in the run line (the code gate stays closed)
        $kdNote = $(if (-not $keptDays.ok) { " -- PIM_UPDATE_NIGHTLY_DAYS '$kd' cannot be read: CODE updates stay CLOSED (security check only) until Deploy-PimUpdateJob is re-run (fix by hand)" } else { '' })
        if ($cur -eq $want) { return @{ action = 'none'; cron = $cur; nightlyUtc = $n.text; nightlyDays = $kd; reason = "every 15 minutes, nightly at $($n.text) UTC$kdNote" } }
        return @{ action = 'quarter'; cron = $want; nightlyUtc = $n.text; nightlyDays = $kd; reason = "the 15-minute cron did not match the nightly time $($n.text) -- corrected$kdNote" }
    }
    if ($isQuarter) { return @{ action = 'none'; cron = $cur; nightlyUtc = ''; nightlyDays = $kd; reason = 'a 15-minute cron with no nightly time (PIM_UPDATE_NIGHTLY_UTC) -- left as it is; re-run Deploy-PimUpdateJob' } }
    # not daily, not quarter-hourly: the quarter-hour slot is restored on the nightly minute the job keeps (else setup's 03:00)
    $nn = $(if ($n.ok) { $n } else { ConvertFrom-PimUpdateNowNightly -Text '03:00' })
    $src = $(if ($n.ok) { "PIM_UPDATE_NIGHTLY_UTC $($nn.text)" } else { "no readable nightly time -- setup's default $($nn.text)" })
    return @{ action = 'quarter'; cron = (Get-PimUpdateNowQuarterCron -Minute $nn.minute); nightlyUtc = $nn.text; nightlyDays = $kd
              reason = "the updater's cron '$cur' has no 15-minute slot -- restored on the nightly time ($src) UTC: the security check runs every 15 minutes" }
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
        -Enabled          Test-PimUpdateNowEnabled -- IGNORED since SEC-PATCH-PIPELINE-1 pt 9 (was: $false = legacy, every
                          execution a full run); the quarter-hour slot is always 'quick' (the security check)
      A scheduled execution starts on a 15-minute slot (the nightly minute's quarter-hour minutes), within -ToleranceSeconds.
      Off-slot, or not the FIRST execution of its slot (the scheduled one already ran) = somebody started it = manual.
    #>
    param([AllowNull()][AllowEmptyString()][string]$NightlyUtc, [Parameter(Mandatory)][datetime]$StartUtc, [AllowNull()][object[]]$Executions = $null,
          [AllowNull()][AllowEmptyString()][string]$OwnExecution = '', [int]$ToleranceSeconds = 120, [bool]$Enabled = $true,
          # 3.1.72 review N2/C2: PIM_UPDATE_NIGHTLY_DAYS ('' = every day). The nightly TIME on a day outside it is a 'quick'
          # (security-only) slot -- the install's own code cadence is never widened.
          [AllowNull()][AllowEmptyString()][string]$NightlyDays = '')
    $n = ConvertFrom-PimUpdateNowNightly -Text $NightlyUtc
    $s = $StartUtc.ToUniversalTime()
    if (-not $n.ok) { return @{ kind = 'legacy'; reason = 'the updater runs on its nightly cron (no PIM_UPDATE_NIGHTLY_UTC) -- a full run, as before'; startUtc = $s; slotUtc = $null } }
    # SEC-PATCH-PIPELINE-1 pt 9 (Invardia 2026-11-27): -Enabled (PIM_UPDATE_NOW) no longer makes every execution a full run --
    # a scheduled quarter-hour slot is ALWAYS 'quick' (it carries the security check; security is not something an operator
    # opts out of), and the quick check itself stops only feature updates when UPDATE NOW is off. A hand-started execution is
    # still 'manual' (off-slot, or not the slot's first) -- never a do-nothing check. -Enabled is kept for callers.
    $q = Get-PimUpdateNowSlotMinutes
    $o = $n.minute % $q
    $back = (($s.Minute - $o) % $q + $q) % $q
    $slot = (New-Object datetime ($s.Year, $s.Month, $s.Day, $s.Hour, $s.Minute, 0, [DateTimeKind]::Utc)).AddMinutes(-$back)
    $isNightlyTime = ($slot.Hour -eq $n.hour -and $slot.Minute -eq $n.minute)
    if ($isNightlyTime -and (Test-PimUpdateNowDayMatch -Days $NightlyDays -DateUtc $slot)) {
        return @{ kind = 'nightly'; reason = "the nightly slot ($($n.text) UTC) -- the normal update"; startUtc = $s; slotUtc = $slot }
    }
    if ($isNightlyTime -and ($s - $slot).TotalSeconds -le $ToleranceSeconds) {
        # N2/C2: the nightly time, not a nightly day -> the scheduled security check of this slot (a hand start stays manual below)
        $own0 = "$OwnExecution".Trim(); $taken = $false
        foreach ($e in @($Executions | Where-Object { $null -ne $_ })) { if ($own0 -and "$($e.name)" -eq $own0) { continue }; if ($null -ne $e.startUtc -and $e.startUtc -ge $slot -and $e.startUtc -lt $s) { $taken = $true } }
        if (-not $taken) { return @{ kind = 'quick'; reason = ("the {0:HH:mm} UTC slot is the nightly time, but not a nightly day ('{1}') -- the security check only" -f $slot, "$NightlyDays".Trim()); startUtc = $s; slotUtc = $slot; offDay = $true } }
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

function Test-PimUpdateNowImageOnly {
    <#
      PURE. IMAGE-30MIN-1 / SEC-LANE-1 G5 (Invardia decision 2026-11-24, the same rule as EPS 2.1.64 and SI): is -Target a NEWER
      image-only build (<x.y.z>.N) of the x.y.z this install runs? Then the 15-minute quick check applies it at once, without an
      expedite mark and without waiting for the nightly slot. The SAME rule as Get-PimImageOnlyUpdateDecision
      (PIM-UpdateLifecycle.ps1, loaded only later in the updater) -- Test-PimUpdateNow proves the two agree.
    #>
    param([AllowEmptyString()][string]$Running = '', [AllowEmptyString()][string]$Target = '')
    $tm = [regex]::Match("$Target".Trim(), '^(\d+\.\d+\.\d+)\.(\d+)$'); if (-not $tm.Success) { return $false }
    $rm = [regex]::Match("$Running".Trim(), '^(\d+\.\d+\.\d+)(?:\.(\d+))?$'); if (-not $rm.Success) { return $false }
    if ($tm.Groups[1].Value -ne $rm.Groups[1].Value) { return $false }
    $rN = $(if ($rm.Groups[2].Success) { [int]$rm.Groups[2].Value } else { 0 })
    return ([int]$tm.Groups[2].Value -gt $rN)
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
        no install key (community / Invardia-less: NO call) -> no ring -> the signal (404 / 0 / 5xx =
        no signal, quietly; 304 = the stored one) -> updateNow false -> older than 24 h -> already acted on (raisedAt) ->
        not newer than the installed version -> PIM_UPDATE_HOLD -> another updater execution running (guard Strict mode is
        NEVER a gate: owner 2026-11-09 "strict mode can never block an update")
        (unreadable = not started).
        -Enabled $false (PIM_UPDATE_NOW=0) = SECURITY ONLY (SEC-PATCH-PIPELINE-1 pt 9): the same one call is made, and an
        update-now / expedite for anything but a newer image-only build of the running release is not started here (it
        waits for the nightly window) -- securityOnly = $true in the result.
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
    $res = @{ run = $false; line = ''; signal = $null; stateSaved = $false; source = ''; imageOnly = $false; securityOnly = $false }
    try {
        $now = $NowUtc.ToUniversalTime()
        $ringN = -1; [void][int]::TryParse("$Ring".Trim(), [ref]$ringN)
        # SEC-PATCH-PIPELINE-1 pt 9 (Invardia 2026-11-27; SEC-LANE-1 G5 / IMAGE-30MIN-1): security is not something an operator
        # opts out of -- with UPDATE NOW OFF the check still runs (the same one /head call); only an image-only release of the
        # running build may start an update then (gate below). (Was: off -> "nothing checked", no call.)
        $res.securityOnly = (-not $Enabled)
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
                    # IMAGE-30MIN-1 (SEC-LANE-1 G5): a newer image-only build of the running release needs no expedite mark --
                    # it is applied in THIS slot (once per version: the signal key is version#sequence#now). A code release
                    # still waits for an expedite or the nightly slot. Running jobs are never stopped (images only).
                    # UPDATE NOW off (security only): an image-only release is applied now even when Invardia marked it 'window'.
                    if ($hp.ok -and (-not $hp.apply -or -not $Enabled) -and (Test-PimUpdateNowImageOnly -Running $RunningVersion -Target "$($hp.version)")) {
                        $hp.apply = 'now'; $hp.reason = 'image-only security release (IMAGE-30MIN-1)'; $res.imageOnly = $true
                    }
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
        if (-not $Enabled) {
            # security only: a code release (an expedite, or the old /signal for a non-image-only version) waits for the nightly
            # window, exactly as before; an image-only build of the running release goes on through every gate below.
            if (-not $isHead -and (Test-PimUpdateNowImageOnly -Running $RunningVersion -Target "$($sig.version)")) { $res.imageOnly = $true }
            if (-not $res.imageOnly) {
                & $save "update now: off for ring $ringN (PIM_UPDATE_NOW) -- the security check ran; $($sig.version) is a code release, not an image-only one of $RunningVersion -- it waits for the nightly window"
                return $res
            }
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
        $who = $(if ($isHead -and $res.imageOnly) { "ring $ringN (image-only security release, applied at once)" } elseif ($isHead) { "ring $ringN (expedite $($sig.apply))" } elseif ($sig.scope -eq 'environment') { 'this environment' } else { "ring $ringN" })
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

# ---- ROLL-RETRY-1 (found 2026-11-11): a roll HELD by the schema quiesce is retried by the next 15-minute run ----------------
# A nightly roll that the quiesce deferred (a PIM job still running at the bound) records UpdateState { action 'schema';
# outcome 'waiting' }. Before this, every following 15-minute check said "nothing to do (the nightly run covers it)" and the
# install waited 24 h. Now a quick run whose recorded state is that hold, and whose ring head is AHEAD of the running version,
# runs the normal update in this execution -- the same path as the nightly, the same quiesce rule (waits for no PIM job
# running, never stops anything; a SHORTER wait, Get-PimUpdateRetryQuiesceWaitMinutes, and no long-job extension, so runs do
# not pile up), never a major jump, the same health check / rollback. At most one attempt per 15-minute run; never while
# another updater execution runs. An expedite (Update now) keeps its own path.
function Get-PimUpdateRetryQuiesceWaitMinutes { <# PURE. LITERAL. The quiesce bound of a RETRY run (the nightly's is 20 min). #> return 5 }
function Get-PimUpdateRetryMaxAgeHours        { <# PURE. LITERAL. A hold recorded longer ago than this is not retried (the nightly run takes it). #> return 26 }

# ---- BUILD-TRANSIENT-1 (2026-11-17): a build that failed on a passing registry fault is retried by the next update run -----
# The build of the new image failed on a fault that goes away by itself (a base-image pull timeout, a reset, a registry 5xx, a
# 429, an ARM 409 -- Get-PimAcrBuildTransientCause) and failed again on the in-run retry. The run records it in UpdateState
# with Invardia's TRANSIENT-RETRY-1 statement (retry = { transient, willRetry, cause, attempt, priorVersion, priorHealthy });
# the uplink sends it on the updater's run report (Retry), and Invardia holds its alert while transient, willRetry is not
# false and attempt < 3. The next 15-minute run retries the build by the same path as a held roll (Get-PimUpdateRetryDecision:
# never two updater executions at once, never a major jump, the ring's approval stays the authority). Attempts 1 and 2 say
# willRetry true; the 3rd failing attempt says willRetry false -- a real failure, alerted as before. A success clears it (a
# record without retry). The running install is never touched by a failed build.
function Get-PimUpdateBuildRetryMaxAttempts { <# PURE. LITERAL. Invardia's TRANSIENT_REPEAT_RUNS: the attempt that says willRetry false. #> return 3 }

function Get-PimUpdateBuildRetryState {
    <#
      PURE. The TRANSIENT-RETRY-1 statement of a recorded build failure, or $null: the record is a run record with action
      'built', outcome 'failed' and a retry whose transient is $true. Returns @{ attempt; willRetry; cause; targetVersion; tsUtc }.
    #>
    param([AllowNull()][object]$State)
    $st = ConvertFrom-PimUpdateNowStored $State
    if ($null -eq $st) { return $null }
    $kind = "$(Get-PimUpdateNowField $st 'kind')".Trim()
    if ($kind -and $kind -ne 'run') { return $null }
    if ("$(Get-PimUpdateNowField $st 'action')".Trim() -ne 'built' -or "$(Get-PimUpdateNowField $st 'outcome')".Trim() -ne 'failed') { return $null }
    $rt = Get-PimUpdateNowField $st 'retry'
    if ($null -eq $rt -or $rt -is [string]) { return $null }
    $tf = Get-PimUpdateNowField $rt 'transient'
    if (-not ($tf -is [bool]) -or -not $tf) { return $null }
    $at = 0; [void][int]::TryParse("$(Get-PimUpdateNowField $rt 'attempt')", [ref]$at); if ($at -lt 1) { $at = 1 }
    $wr = Get-PimUpdateNowField $rt 'willRetry'
    return @{ attempt = $at; willRetry = [bool]($wr -is [bool] -and $wr); cause = "$(Get-PimUpdateNowField $rt 'cause')".Trim()
              targetVersion = "$(Get-PimUpdateNowField $st 'targetVersion')".Trim(); tsUtc = (ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $st 'tsUtc')) }
}

function New-PimUpdateBuildRetryInfo {
    <#
      PURE. THIS run's TRANSIENT-RETRY-1 statement for a build that failed on a passing fault (Invardia uplink.ts RetryInfo):
        [ordered]@{ transient = $true; willRetry; cause; attempt; priorVersion; priorHealthy }
      attempt = 1, or the previous record's attempt + 1 when that record is a transient build failure of the SAME target
      version recorded less than Get-PimUpdateRetryMaxAgeHours ago. willRetry = attempt < Get-PimUpdateBuildRetryMaxAttempts.
      A cause outside Invardia's list -> 'other'. priorHealthy: $true / $false, or $null when the running Manager was not read.
      -QuickRuns $false = this install has no 15-minute update runs (the updater runs only nightly): nothing retries it soon,
      so willRetry is false at once -- an alert is never held for days.
    #>
    param([AllowNull()][object]$Previous, [AllowEmptyString()][string]$Cause = '', [AllowEmptyString()][string]$TargetVersion = '',
          [AllowEmptyString()][string]$PriorVersion = '', [AllowNull()][object]$PriorHealthy = $null, [bool]$QuickRuns = $true,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $known = @('arm-409', 'image-pull-timeout', 'queue-start-timeout', 'request-timeout', 'throttled', 'server-error', 'other')
    $c = "$Cause".Trim().ToLowerInvariant(); if ($known -notcontains $c) { $c = 'other' }
    $attempt = 1
    $pv = Get-PimUpdateBuildRetryState -State $Previous
    if ($pv -and $pv.targetVersion -and $pv.targetVersion -eq "$TargetVersion".Trim() -and $null -ne $pv.tsUtc -and
        ($NowUtc.ToUniversalTime() - $pv.tsUtc).TotalHours -lt (Get-PimUpdateRetryMaxAgeHours)) { $attempt = [int]$pv.attempt + 1 }
    $ph = $null; if ($PriorHealthy -is [bool]) { $ph = [bool]$PriorHealthy }
    return [ordered]@{ transient = $true; willRetry = [bool]($QuickRuns -and $attempt -lt (Get-PimUpdateBuildRetryMaxAttempts)); cause = $c; attempt = [int]$attempt
                       priorVersion = "$PriorVersion".Trim(); priorHealthy = $ph }
}

function Get-PimUpdateRetryDecision {
    <#
      PURE. Should THIS 15-minute (quick) run retry a roll the schema quiesce held?
        -State          the recorded UpdateState (pim.Settings 'UpdateState': object, hashtable or JSON text; $null = none)
        -RunningVersion the Manager version running now
        -HeadVersion    Invardia's head for this install's ring ('' = not known this run)
        -Expedite       an expedite / update-now signal is set (its own path decides; never a retry here)
        -Hold           PIM_UPDATE_HOLD=1
        -OtherRunning   another updater execution is running: $true / $false / $null (not readable)
      Returns @{ retry; reason; line; heldUtc; headVersion; waitMinutes }:
        reason  expedite | not-held | stale | no-head | unreadable | not-ahead | major | hold | busy | unreadable-runs | retry
                BUILD-TRANSIENT-1, for a recorded transient build failure: retry-spent | build-retry (and the guards above)
        line    '' when the recorded state is NOT a quiesce hold (the caller says its usual line); else the one line to say.
        attempt BUILD-TRANSIENT-1: the attempt a build retry makes (the recorded attempt + 1); 0 otherwise.
    #>
    param([AllowNull()][object]$State, [AllowEmptyString()][string]$RunningVersion = '', [AllowEmptyString()][string]$HeadVersion = '',
          [bool]$Expedite = $false, [bool]$Hold = $false, [AllowNull()][object]$OtherRunning = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = @{ retry = $false; reason = 'not-held'; line = ''; heldUtc = $null; headVersion = "$HeadVersion".Trim(); waitMinutes = (Get-PimUpdateRetryQuiesceWaitMinutes); attempt = 0 }
    if ($Expedite) { $res.reason = 'expedite'; return $res }
    $st = ConvertFrom-PimUpdateNowStored $State
    if ($null -eq $st) { return $res }
    $kind = "$(Get-PimUpdateNowField $st 'kind')".Trim()
    if ($kind -and $kind -ne 'run') { return $res }
    # BUILD-TRANSIENT-1: a build that failed on a passing registry fault (and said it will be retried) is retried here, by the
    # same rules as a held roll: the ring's head ahead of the running version, never a major jump, never held, never two at once.
    $bt = Get-PimUpdateBuildRetryState -State $st
    if ($bt) {
        $now = $NowUtc.ToUniversalTime()
        $res.heldUtc = $bt.tsUtc
        $at = $(if ($null -ne $bt.tsUtc) { $bt.tsUtc.ToString('yyyy-MM-dd HH:mm:ss') + 'Z' } else { 'an unknown time' })
        $max = Get-PimUpdateBuildRetryMaxAttempts
        $pre = "update retry: the build that failed at $at on a passing registry fault ($($bt.cause); attempt $($bt.attempt) of $max)"
        if (-not $bt.willRetry) { $res.reason = 'retry-spent'; $res.line = "$pre was the last retry -- not retried here (the nightly run takes it)"; return $res }
        if ($null -eq $bt.tsUtc -or ($now - $bt.tsUtc).TotalHours -ge (Get-PimUpdateRetryMaxAgeHours)) {
            $res.reason = 'stale'; $res.line = "$pre is older than $(Get-PimUpdateRetryMaxAgeHours) h -- not retried here (the nightly run takes it)"; return $res
        }
        $hv = "$HeadVersion".Trim()
        if (-not $hv) { $res.reason = 'no-head'; $res.line = "$pre -- the ring's head is not known this run, so it is not retried now (the next 15-minute run asks again)"; return $res }
        $cmp = Compare-PimUpdateNowVersion -A $hv -B $RunningVersion
        if ($null -eq $cmp) { $res.reason = 'unreadable'; $res.line = "$pre -- the head ('$hv') or the running version ('$RunningVersion') cannot be read; not retried"; return $res }
        if ($cmp -le 0) { $res.reason = 'not-ahead'; $res.line = "$pre -- the ring's head $hv is not ahead of the running $RunningVersion; nothing to do"; return $res }
        $rm = -1; $tm = -1
        if ("$RunningVersion".Trim().TrimStart('v', 'V') -match '^(\d+)\.') { $rm = [int]$Matches[1] }
        if ($hv.TrimStart('v', 'V') -match '^(\d+)\.') { $tm = [int]$Matches[1] }
        if ($rm -ge 0 -and $tm -gt $rm) { $res.reason = 'major'; $res.line = "$pre -- $RunningVersion -> $hv is a MAJOR jump; a retry never takes one (the nightly run decides)"; return $res }
        if ($Hold) { $res.reason = 'hold'; $res.line = "$pre -- this environment is HELD (PIM_UPDATE_HOLD=1); not retried"; return $res }
        if ($OtherRunning -is [bool] -and $OtherRunning) { $res.reason = 'busy'; $res.line = "$pre -- another updater execution is running; not retried now (never two at once)"; return $res }
        if (-not ($OtherRunning -is [bool])) { $res.reason = 'unreadable-runs'; $res.line = "$pre -- the updater's executions could not be read; not retried now (never two at once)"; return $res }
        $res.retry = $true; $res.reason = 'build-retry'; $res.attempt = [int]$bt.attempt + 1
        $res.line = "update retry: building again -- the build failed at $at on a passing registry fault ($($bt.cause)); this is attempt $($res.attempt) of $max (ring head $hv, running $RunningVersion; the running version stays as it is until a build succeeds)"
        return $res
    }
    if ("$(Get-PimUpdateNowField $st 'outcome')".Trim() -ne 'waiting' -or "$(Get-PimUpdateNowField $st 'action')".Trim() -ne 'schema') { return $res }
    $held = ConvertTo-PimUpdateNowUtc (Get-PimUpdateNowField $st 'tsUtc')
    $res.heldUtc = $held
    $now = $NowUtc.ToUniversalTime()
    $at = $(if ($null -ne $held) { $held.ToString('yyyy-MM-dd HH:mm:ss') + 'Z' } else { 'an unknown time' })
    $pre = "update retry: the roll held at $at by a running job"
    if ($null -eq $held -or ($now - $held).TotalHours -ge (Get-PimUpdateRetryMaxAgeHours)) {
        $res.reason = 'stale'; $res.line = "$pre is older than $(Get-PimUpdateRetryMaxAgeHours) h -- not retried here (the nightly run takes it)"; return $res
    }
    $hv = "$HeadVersion".Trim()
    if (-not $hv) { $res.reason = 'no-head'; $res.line = "$pre -- the ring's head is not known this run, so it is not retried now (the next 15-minute run asks again)"; return $res }
    $cmp = Compare-PimUpdateNowVersion -A $hv -B $RunningVersion
    if ($null -eq $cmp) { $res.reason = 'unreadable'; $res.line = "$pre -- the head ('$hv') or the running version ('$RunningVersion') cannot be read; not retried"; return $res }
    if ($cmp -lt 0) { $res.reason = 'not-ahead'; $res.line = "$pre -- the ring's head $hv is not ahead of the running $RunningVersion; nothing to do"; return $res }
    # SCHEMA-FOLLOWUP-1 (2026-11-16, 3.1.40 at ring 0): the held run can be the FOLLOW-UP run on the SAME version -- the run the
    # new updater makes so ITS code applies ITS schema (the roll's own schema step ran with the previous updater's code, which
    # does not know the new tables). Head == running is then NOT "nothing to do": the new schema is still missing (measured:
    # pim.DirectoryPrincipal absent, the people picker failed until a later run). Retry it: the same path, the same quiesce.
    $schemaOnly = ($cmp -eq 0)
    $rm = -1; $tm = -1
    if ("$RunningVersion".Trim().TrimStart('v', 'V') -match '^(\d+)\.') { $rm = [int]$Matches[1] }
    if ($hv.TrimStart('v', 'V') -match '^(\d+)\.') { $tm = [int]$Matches[1] }
    if ($rm -ge 0 -and $tm -gt $rm) { $res.reason = 'major'; $res.line = "$pre -- $RunningVersion -> $hv is a MAJOR jump; a retry never takes one (the nightly run decides)"; return $res }
    if ($Hold) { $res.reason = 'hold'; $res.line = "$pre -- this environment is HELD (PIM_UPDATE_HOLD=1); not retried"; return $res }
    if ($OtherRunning -is [bool] -and $OtherRunning) { $res.reason = 'busy'; $res.line = "$pre -- another updater execution is running; not retried now (never two at once)"; return $res }
    if (-not ($OtherRunning -is [bool])) { $res.reason = 'unreadable-runs'; $res.line = "$pre -- the updater's executions could not be read; not retried now (never two at once)"; return $res }
    $res.retry = $true
    if ($schemaOnly) {
        $res.reason = 'schema-pending'
        $res.line = "update retry: retrying the schema step held at $at by a running job -- running $RunningVersion is the ring head, its own schema step still has to run (the same quiesce rule: waits up to $($res.waitMinutes) min for no PIM job running, nothing is stopped)"
        return $res
    }
    $res.reason = 'retry'
    $res.line = "update retry: retrying the roll held at $at by a running job -- ring head $hv, running $RunningVersion (the same quiesce rule: waits up to $($res.waitMinutes) min for no PIM job running, nothing is stopped)"
    return $res
}

function Get-PimUpdateNowApprovalDecision {
    <#
      PURE. The ring stays the authority: the signal says NOW, never WHICH version. @{ ok; line }:
        the ring approves nothing / an unreadable version  -> not ok
        the ring approves a version OLDER than the signal's -> not ok (not approved for this ring yet)
        the ring's version is not newer than the installed  -> not ok
        else ok (the update runs; it installs what the RING approves)
      3.1.72 review N1/C1 (2026-11-27): -ImageOnly = the run was let through by an IMAGE-ONLY signal (IMAGE-30MIN-1, also the
      security-only slot of SEC-PATCH-PIPELINE-1 pt 9). Then it may start ONLY when the ring-approved version is itself an
      image-only build of the RUNNING version (Test-PimUpdateNowImageOnly); a code release the ring approves is not rolled
      by it -- not ok, "waits for the nightly window", nothing changed. This holds with UPDATE NOW on as well.
    #>
    param([AllowEmptyString()][string]$SignalVersion = '', [AllowEmptyString()][string]$ApprovedVersion = '', [AllowEmptyString()][string]$RunningVersion = '', [AllowEmptyString()][string]$Ring = '',
          [bool]$ImageOnly = $false)
    $a = "$ApprovedVersion".Trim()
    if (-not $a) { return @{ ok = $false; line = "update now: ring $Ring approves no version -- the signal's $SignalVersion is not approved for this ring; nothing started" } }
    if ($ImageOnly -and -not (Test-PimUpdateNowImageOnly -Running $RunningVersion -Target $a)) {
        return @{ ok = $false; line = "update now: the image-only security release $SignalVersion let this slot through, but ring $Ring approves $a -- not an image-only build of the running $RunningVersion; it waits for the nightly window (nothing changed)" }
    }
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
        $plan = Get-PimUpdateNowSelfCronPlan -CurrentCron $cur -NightlyUtc (& $envOf $j 'PIM_UPDATE_NIGHTLY_UTC') -Enabled $Enabled -NightlyDays (& $envOf $j 'PIM_UPDATE_NIGHTLY_DAYS')
        $res.action = $plan.action
        if ($plan.action -eq 'none') { $res.detail = "update now: cron '$cur' -- $($plan.reason)"; return $res }
        $want = "$($plan.cron)"; $nightly = "$($plan.nightlyUtc)"
        # 3.1.72 review N2/C2: the CODE day pattern rides along -- PIM_UPDATE_NIGHTLY_DAYS set for a weekly / monthly cron, left
        # off (removed) for every day
        $days = "$($plan.nightlyDays)".Trim(); $daysEvery = (-not $days -or $days -eq (Get-PimUpdateNowEveryDay))
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
                    foreach ($v in @($target.env)) { if ($v -and "$($v.name)" -notin @('PIM_UPDATE_NIGHTLY_UTC', 'PIM_UPDATE_NIGHTLY_DAYS')) { $envList.Add($v) | Out-Null } }
                    $envList.Add([pscustomobject]@{ name = 'PIM_UPDATE_NIGHTLY_UTC'; value = $nightly }) | Out-Null
                    if (-not $daysEvery) { $envList.Add([pscustomobject]@{ name = 'PIM_UPDATE_NIGHTLY_DAYS'; value = $days }) | Out-Null }
                    $target | Add-Member -NotePropertyName 'env' -NotePropertyValue @($envList.ToArray()) -Force
                }
            }
            & $Arm 'PATCH' $path @{ properties = @{ configuration = $cfg; template = $tpl } } })
        $back = & $Arm 'GET' $path $null
        $got = "$($back.properties.configuration.scheduleTriggerConfig.cronExpression)"
        if ($got -ne $want) { $res.ok = $false; $res.detail = "update now: wrote cron '$want' but read back '$got' -- the next full run tries again"; return $res }
        if ($nightly -and (& $envOf $back 'PIM_UPDATE_NIGHTLY_UTC') -ne $nightly) { $res.ok = $false; $res.detail = "update now: cron '$want' written, but PIM_UPDATE_NIGHTLY_UTC did not read back -- the next full run tries again"; return $res }
        if ($nightly -and -not $daysEvery -and (& $envOf $back 'PIM_UPDATE_NIGHTLY_DAYS') -ne $days) { $res.ok = $false; $res.detail = "update now: cron '$want' written, but PIM_UPDATE_NIGHTLY_DAYS did not read back -- the next full run tries again"; return $res }
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
