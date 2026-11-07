#Requires -Version 5.1
<#
.SYNOPSIS
  OPEN-13 / framework 8.8 UPDATE-TRACK (owner 2026-10-09: "same with the updater telemetry"): every Pro update run reports
  its STAGES to Invardia, like a tracked install. Used by the updater (tools/pim-engine/update-job-entry.ps1).

.DESCRIPTION
  Contract (Invardia, live -- the same events endpoint as a tracked install, tools/setup/_PimInstallTracking.ps1):
    open   POST {base}/api/install/runs   header X-Invardia-Install-Key: <the install key>   (the uplink's / update pull's key)
           {"productId":"pim-manager","kind":"update","ring":0-3,"fromVersion":"<running>","toVersion":"<target>"}
           -> 201 { runId, token, eventsUrl, statusUrl }
    event  POST {eventsUrl}   header X-Invardia-Install-Token: <token>
           {"seq":N,"step":{"id","title"},"state":"started|ok|warning|failed|skipped|waiting|completed","at":"<ISO UTC>",
            "durationMs":<ms>,"message":"<one plain line>","errorClass":"<class>"(failed only)}
  Stage ids (stable, every product): check, download, verify, build, apply, migrate, health, then done (completed) |
  failed (the failed stage is the last event) | rollback (rolled back to the last good image, then done completed
  "rolled back"). PIM changes the schema BEFORE it rolls (additive-only, DESIGN "schema before containers"), so its
  order is check -> download -> verify -> build -> migrate -> apply -> health -> done.

  The run is opened LAZILY: 'check' starts when the update decision starts, but the open call needs the target version,
  so the events wait in memory until the decision is known (or the run ends) and are then sent in order, each with the
  time it happened. ONLY A RUN THAT MOVES A VERSION IS REPORTED (Test-PimUpdateTrackDue: the plan builds or rolls to a
  target that is not the running one): a run that ends with nothing to do, ahead, held, or before an update was known to be
  due is never opened and sends nothing -- its waiting events are dropped.

  BEST EFFORT, ALWAYS: a failed open / post stops the tracking for this run with ONE log line; the update itself never
  waits for, fails on or changes because of a report. Every call is bounded (15 s, no retry).
  INERT without an install key (a Community install has none), without a ring 0-3, without a plain running version, or
  with PIM_UPDATE_TRACK = 0/false/off/no on the updater job (ON by default).
  NO SECRETS: the key and the token are only ever headers; every message is one scrubbed line.

  PURE except the default HTTP seam. ASCII; 5.1 + 7.
#>
Set-StrictMode -Off

$script:PimUpdateTrackProduct = 'pim-manager'
$script:PimUpdateTrackDefaultBase = 'https://invardia.com'

function Get-PimUpdateTrackStages { <# PURE. LITERAL. Invardia's closed list of update step ids (core install.ts UPDATE_STEPS). #> return @('check', 'download', 'verify', 'build', 'apply', 'migrate', 'health', 'done', 'failed', 'rollback') }

function Get-PimUpdateTrackStageTitle {
    <# PURE. The plain title Invardia shows for a stage. #>
    param([Parameter(Mandatory)][string]$Stage)
    switch ("$Stage") {
        'check'    { return 'Check for an approved version' }
        'download' { return 'Download the release' }
        'verify'   { return 'Verify the release' }
        'build'    { return 'Build the image' }
        'migrate'  { return 'Database schema' }
        'apply'    { return 'Roll out the new version' }
        'health'   { return 'Health check' }
        'rollback' { return 'Roll back to the last good version' }
        'done'     { return 'Update finished' }
    }
    return "$Stage"
}

function Test-PimUpdateTrackOn {
    <# PURE. PIM_UPDATE_TRACK: ON by default; only 0 / false / off / no switches it off. #>
    param([AllowNull()][string]$Value)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function ConvertTo-PimUpdateTrackBase {
    <# PURE. The Invardia origin: '' -> https://invardia.com; a plain https origin (no path, query or space) else '' (= off). #>
    param([AllowNull()][string]$BaseUrl)
    $b = "$BaseUrl".Trim().TrimEnd('/')
    if (-not $b) { return $script:PimUpdateTrackDefaultBase }
    if ($b -match '^https://[^\s/?#]+$') { return $b }
    return ''
}

function ConvertTo-PimUpdateTrackRing {
    <# PURE. 'ring2' / 'Ring 2' / '2' -> 2; anything not 0..3 -> $null. #>
    param([AllowNull()][object]$Ring)
    $n = ("$Ring".Trim() -replace '^(?i)ring[\s_-]*', ''); $r = 0
    if ($n -and [int]::TryParse($n, [ref]$r) -and $r -ge 0 -and $r -le 3) { return $r }
    return $null
}

function Test-PimUpdateTrackVersion {
    <# PURE. Invardia's version shape: ^[0-9A-Za-z][0-9A-Za-z.+-]{0,49}$. #>
    param([AllowNull()][string]$Version)
    return [bool]("$Version".Trim() -match '^[0-9A-Za-z][0-9A-Za-z.+-]{0,49}$')
}

function New-PimUpdateTrackOpenBody {
    <# PURE. The open body, exactly the five keys Invardia takes, or $null when one value is not in its shape. #>
    param([AllowNull()][object]$Ring, [AllowNull()][string]$FromVersion, [AllowNull()][string]$ToVersion)
    $r = ConvertTo-PimUpdateTrackRing -Ring $Ring
    if ($null -eq $r -or -not (Test-PimUpdateTrackVersion $FromVersion) -or -not (Test-PimUpdateTrackVersion $ToVersion)) { return $null }
    return [ordered]@{ productId = $script:PimUpdateTrackProduct; kind = 'update'; ring = [int]$r; fromVersion = "$FromVersion".Trim(); toVersion = "$ToVersion".Trim() }
}

function Protect-PimUpdateTrackText {
    <# PURE. One plain line, at most 400 characters, with anything credential-shaped replaced by '***' (the install-tracking rules). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text" -replace "[\r\n\t]+", ' '
    $t = $t -replace '(?i)\bBearer\s+[A-Za-z0-9\-\._~\+/]+=*', 'Bearer ***'
    $t = $t -replace '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*)?', '***'
    $t = $t -replace '\b(inv|ek)-[A-Za-z0-9_-]{12,}', '$1-***'
    $t = $t -replace '(?i)([?&](sig|se|sp|sv|st|skoid|sktid|skt|ske|sks|skv|sr|spr)=)[^&\s]+', '$1***'
    $t = $t -replace '(?i)\b(password|passwd|pwd|secret|clientsecret|client_secret|apikey|api_key|token|accountkey|sharedaccesskey)(\s*[=:]\s*)("[^"]*"|''[^'']*''|\S+)', '$1$2***'
    $t = ($t -replace '\s{2,}', ' ').Trim()
    if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + ' ...' }
    return $t
}

function Get-PimUpdateTrackErrorClass {
    <# PURE. The failed stage's class ('pim-update.<stage>', a registry push fault 'pim-update.registry-push'); Invardia's shape. #>
    param([AllowNull()][string]$Stage, [AllowNull()][string]$ErrorText)
    $s = "$Stage".Trim().ToLowerInvariant(); if ($s -notmatch '^[a-z]{1,20}$') { $s = 'check' }
    if ("$ErrorText" -match '(?i)push to the registry failed') { return 'pim-update.registry-push' }
    return "pim-update.$s"
}

function Invoke-PimUpdateTrackHttp {
    <# The real HTTP seam: param($Method, $Url, $Headers, $BodyJson) -> @{ status; body }. 15 s, no retry; a non-2xx is a status. #>
    param([string]$Method, [string]$Url, [hashtable]$Headers, [string]$BodyJson)
    try {
        $r = Invoke-WebRequest -Method $Method -Uri $Url -Headers $Headers -Body $BodyJson -ContentType 'application/json' -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { } }
        return @{ status = [int]$r.StatusCode; body = $b }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        return @{ status = $code; body = $null; error = "$($_.Exception.Message)" }
    }
}

function New-PimUpdateTrack {
    <#
      A tracker for ONE update run. Inert (every call a no-op) unless -Enabled, an install key in Invardia's shape, a ring
      0..3 and a usable base. -Http: TEST seam (Invoke-PimUpdateTrackHttp shape); -Clock: [datetime] UTC; -Log { param($Line) }.
    #>
    param([bool]$Enabled = $true, [AllowNull()][string]$InstallKey = '', [AllowNull()][string]$BaseUrl = '', [AllowNull()][object]$Ring = $null,
          [scriptblock]$Http = $null, [scriptblock]$Clock = $null, [scriptblock]$Log = $null)
    $key = "$InstallKey".Trim(); $base = ConvertTo-PimUpdateTrackBase -BaseUrl $BaseUrl; $rn = ConvertTo-PimUpdateTrackRing -Ring $Ring
    $why = ''
    if (-not $Enabled) { $why = 'switched off (PIM_UPDATE_TRACK)' }
    elseif ($key -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { $why = 'no install key (a Pro install reports its update stages)' }
    elseif ($null -eq $rn) { $why = 'no update ring 0-3' }
    elseif (-not $base) { $why = 'the Invardia address is not a plain https origin' }
    if (-not $Http) { $Http = { param($m, $u, $h, $b) Invoke-PimUpdateTrackHttp -Method $m -Url $u -Headers $h -BodyJson $b } }
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    return [pscustomobject]@{
        enabled = (-not $why); why = $why; key = $key; base = $base; ring = $rn; http = $Http; clock = $Clock; log = $Log
        opened = $false; runId = ''; token = ''; eventsUrl = ''; seq = 0; buffer = (New-Object System.Collections.Generic.List[object])
        current = ''; started = @{}; stopped = $false; finished = $false; sent = 0; fromVersion = ''; toVersion = ''
    }
}

function Write-PimUpdateTrackLog {
    param([object]$Track, [string]$Line)
    if ($Track -and $Track.log) { try { & $Track.log ("update track: " + $Line) } catch { } }
}

function Stop-PimUpdateTrack {
    <# One line, then silence: a report that failed never comes back in this run. #>
    param([object]$Track, [string]$Why)
    $Track.stopped = $true; $Track.buffer.Clear()
    Write-PimUpdateTrackLog -Track $Track -Line "stopped ($(Protect-PimUpdateTrackText $Why)) -- the update continues; Invardia shows this run as incomplete"
}

function Send-PimUpdateTrackEventNow {
    param([object]$Track, [object]$Ev)
    $body = $Ev | ConvertTo-Json -Depth 5 -Compress
    $r = $null
    try { $r = & $Track.http 'POST' $Track.eventsUrl @{ 'X-Invardia-Install-Token' = $Track.token } $body } catch { $r = @{ status = 0; error = "$($_.Exception.Message)" } }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -lt 200 -or $st -ge 300) { Stop-PimUpdateTrack -Track $Track -Why ("event '{0}' answered {1}{2}" -f "$($Ev.step.id)", $st, $(if ("$($r.error)".Trim()) { ": $($r.error)" })); return $false }
    $Track.sent = [int]$Track.sent + 1
    return $true
}

function Add-PimUpdateTrackEvent {
    <# Queue (not opened yet) or post one event. Never throws. 'started' records the time; the stage's next state carries durationMs. #>
    param([Parameter(Mandatory)][object]$Track, [Parameter(Mandatory)][string]$Stage,
          [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'waiting', 'completed')][string]$State,
          [string]$Message = '', [string]$ErrorClass = '')
    if (-not $Track -or -not $Track.enabled -or $Track.stopped -or $Track.finished) { return $false }
    if ((Get-PimUpdateTrackStages) -notcontains $Stage) { return $false }
    try {
        $now = ([datetime](& $Track.clock)).ToUniversalTime()
        $Track.seq = [int]$Track.seq + 1
        $ev = [ordered]@{ seq = $Track.seq; step = [ordered]@{ id = $Stage; title = (Get-PimUpdateTrackStageTitle -Stage $Stage) }; state = $State; at = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
        if ($State -eq 'started') { $Track.started[$Stage] = $now }
        elseif ($Track.started.ContainsKey($Stage)) { $ev['durationMs'] = [int64][math]::Max([double]0, ($now - [datetime]$Track.started[$Stage]).TotalMilliseconds) }
        $m = Protect-PimUpdateTrackText $Message; if ($m) { $ev['message'] = $m }
        if ($State -eq 'failed' -and "$ErrorClass" -match '^[A-Za-z][A-Za-z0-9._-]{0,39}$') { $ev['errorClass'] = "$ErrorClass" }
        if (-not $Track.opened) { $Track.buffer.Add([pscustomobject]$ev); return $true }
        return (Send-PimUpdateTrackEventNow -Track $Track -Ev ([pscustomobject]$ev))
    } catch { Stop-PimUpdateTrack -Track $Track -Why "$($_.Exception.Message)"; return $false }
}

function Test-PimUpdateTrackDue {
    <# PURE. Does THIS run move a version? The plan builds or rolls, to a plain target version that is NOT the running one.
       Only then is a run opened at Invardia; anything else (none, ahead, held, same version) reports nothing. #>
    param([AllowNull()][string]$PlanAction, [AllowNull()][string]$TargetVersion, [AllowNull()][string]$RunningVersion)
    if ("$PlanAction".Trim() -notin @('build', 'roll')) { return $false }
    $t = "$TargetVersion".Trim()
    if (-not (Test-PimUpdateTrackVersion $t)) { return $false }
    return ($t -ne "$RunningVersion".Trim())
}

function Open-PimUpdateTrack {
    <#
      Open the run at Invardia (once) and send what waited. -ToVersion '' = the running version (a run that ended before a
      target was known). Returns $true when the run is open. Never throws.
    #>
    param([Parameter(Mandatory)][object]$Track, [AllowNull()][string]$FromVersion, [AllowNull()][string]$ToVersion = '')
    if (-not $Track -or -not $Track.enabled -or $Track.stopped) { return $false }
    if ($Track.opened) { return $true }
    $to = "$ToVersion".Trim(); if (-not $to) { $to = "$FromVersion".Trim() }
    $body = New-PimUpdateTrackOpenBody -Ring $Track.ring -FromVersion $FromVersion -ToVersion $to
    if ($null -eq $body) { Stop-PimUpdateTrack -Track $Track -Why "the versions are not plain versions (from '$FromVersion' to '$to')"; return $false }
    $r = $null
    try { $r = & $Track.http 'POST' "$($Track.base)/api/install/runs" @{ 'X-Invardia-Install-Key' = $Track.key } ($body | ConvertTo-Json -Compress) } catch { $r = @{ status = 0; error = "$($_.Exception.Message)" } }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    $get = { param($n) $b = $r.body; if ($null -eq $b) { '' } elseif ($b -is [System.Collections.IDictionary]) { "$($b[$n])" } elseif ($b.PSObject.Properties[$n]) { "$($b.$n)" } else { '' } }
    $tok = "$(& $get 'token')".Trim()
    if ($st -lt 200 -or $st -ge 300 -or -not $tok) {
        $err = "$($r.error)"; if ($Track.key -and $err.Contains($Track.key)) { $err = 'the request failed' }
        Stop-PimUpdateTrack -Track $Track -Why ("Invardia did not open the run (HTTP {0}{1})" -f $st, $(if ($err.Trim()) { ": $err" } elseif (-not $tok -and $st -ge 200 -and $st -lt 300) { ': no token in the answer' }))
        return $false
    }
    $ev = "$(& $get 'eventsUrl')".Trim()
    if ($ev -notmatch '^https://[^\s/?#]+(/[^\s?#]*)?$') { $ev = "$($Track.base)/api/install/events" }
    $Track.token = $tok; $Track.eventsUrl = $ev; $Track.runId = "$(& $get 'runId')".Trim(); $Track.opened = $true
    $Track.fromVersion = "$($body.fromVersion)"; $Track.toVersion = "$($body.toVersion)"
    Write-PimUpdateTrackLog -Track $Track -Line ("run opened at Invardia ({0} -> {1}, ring {2})" -f $body.fromVersion, $body.toVersion, $body.ring)
    $waiting = @($Track.buffer.ToArray()); $Track.buffer.Clear()
    foreach ($e in $waiting) { if (-not (Send-PimUpdateTrackEventNow -Track $Track -Ev $e)) { return $false } }
    return $true
}

function Start-PimUpdateTrackStage {
    <# A new stage starts: the open one (if any, and not this one) is closed 'ok' first. Never throws. #>
    param([Parameter(Mandatory)][object]$Track, [Parameter(Mandatory)][string]$Stage, [string]$Message = '')
    if (-not $Track -or -not $Track.enabled -or $Track.stopped -or $Track.finished) { return $false }
    if ($Track.current -eq $Stage) { return $true }
    if ($Track.current) { [void](Add-PimUpdateTrackEvent -Track $Track -Stage $Track.current -State ok) }
    $Track.current = $Stage
    return (Add-PimUpdateTrackEvent -Track $Track -Stage $Stage -State started -Message $Message)
}

function Close-PimUpdateTrackStage {
    <# The open stage ends with -State (ok | warning | skipped). Never throws. #>
    param([Parameter(Mandatory)][object]$Track, [ValidateSet('ok', 'warning', 'skipped')][string]$State = 'ok', [string]$Message = '')
    if (-not $Track -or -not $Track.enabled -or $Track.stopped -or $Track.finished -or -not $Track.current) { return $false }
    $s = $Track.current; $Track.current = ''
    return (Add-PimUpdateTrackEvent -Track $Track -Stage $s -State $State -Message $Message)
}

function Get-PimUpdateTrackFinalPlan {
    <#
      PURE. How a run's outcome ends its stages: @{ kind = done | failed | waiting | rollback }.
        ok / ahead / skipped        -> done      (the open stage ok, then done completed)
        failed / attention          -> failed    (the open stage failed + errorClass: the LAST event)
        failed + -RolledBack        -> rollback  (the open stage failed, rollback ok, then done completed "rolled back")
        waiting                     -> waiting   (the open stage waiting: the next update run tries again)
    #>
    param([AllowNull()][string]$Outcome, [switch]$RolledBack)
    switch ("$Outcome".Trim().ToLowerInvariant()) {
        { $_ -in @('ok', 'ahead', 'skipped', '') } { return [pscustomobject]@{ kind = 'done' } }
        'waiting' { return [pscustomobject]@{ kind = 'waiting' } }
    }
    if ($RolledBack) { return [pscustomobject]@{ kind = 'rollback' } }
    return [pscustomobject]@{ kind = 'failed' }
}

function Complete-PimUpdateTrack {
    <#
      The run's end (called from the updater's ONE outcome function, so every exit path ends its run). NEVER opens a run (a run
      that was not opened moved no version: its waiting events are dropped, nothing is sent). Never throws; returns $true when the final event was sent.
    #>
    param([Parameter(Mandatory)][object]$Track, [AllowNull()][string]$Outcome = 'ok', [AllowNull()][string]$ErrorText = '',
          [AllowNull()][string]$FromVersion = '', [AllowNull()][string]$ToVersion = '', [switch]$RolledBack)
    if (-not $Track -or -not $Track.enabled -or $Track.stopped -or $Track.finished) { return $false }
    # NEVER OPENS A RUN ITSELF (coordinator review 2026-11-06): a run that was not opened moved no version -- nothing to
    # do, ahead, held, or stopped before an update was known to be due -- and reports NOTHING (no noise at Invardia).
    if (-not $Track.opened) { $Track.buffer.Clear(); $Track.current = ''; $Track.finished = $true; return $false }
    try {
        $plan = Get-PimUpdateTrackFinalPlan -Outcome $Outcome -RolledBack:$RolledBack
        $stage = $(if ($Track.current) { $Track.current } else { 'check' })
        $msg = Protect-PimUpdateTrackText $ErrorText
        $ok = $false
        switch ($plan.kind) {
            'done' {
                if ($Track.current) { [void](Add-PimUpdateTrackEvent -Track $Track -Stage $Track.current -State ok) }
                $ok = Add-PimUpdateTrackEvent -Track $Track -Stage 'done' -State completed -Message $(if ("$Outcome" -eq 'ahead') { 'this environment runs a newer version than its ring approves -- nothing to do' } elseif ($msg) { $msg } else { '' })
            }
            'waiting' { $ok = Add-PimUpdateTrackEvent -Track $Track -Stage $stage -State waiting -Message $msg }
            'failed'  { $ok = Add-PimUpdateTrackEvent -Track $Track -Stage $stage -State failed -Message $msg -ErrorClass (Get-PimUpdateTrackErrorClass -Stage $stage -ErrorText $ErrorText) }
            'rollback' {
                [void](Add-PimUpdateTrackEvent -Track $Track -Stage $stage -State failed -Message $msg -ErrorClass (Get-PimUpdateTrackErrorClass -Stage $stage -ErrorText $ErrorText))
                [void](Add-PimUpdateTrackEvent -Track $Track -Stage 'rollback' -State ok -Message 'rolled back to the last good version')
                $ok = Add-PimUpdateTrackEvent -Track $Track -Stage 'done' -State completed -Message 'rolled back'
            }
        }
        $Track.current = ''; $Track.finished = $true
        return [bool]$ok
    } catch { Stop-PimUpdateTrack -Track $Track -Why "$($_.Exception.Message)"; return $false }
}
