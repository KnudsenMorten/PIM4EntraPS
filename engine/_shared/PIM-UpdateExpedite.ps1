#Requires -Version 5.1
<#
.SYNOPSIS
  The 15-MINUTE EXPEDITE CHECK (framework DOCS/REQUIREMENTS.md 12.1 Phase C; owner: "Ring 0 + 1 always; customers only on
  my word, in agreed hours" -- "Invardia builds the expedite mark; each product builds its updater's short-interval check").

.DESCRIPTION
  Every 15 minutes the installation asks Invardia whether the head of ITS ring carries an "expedite" mark:
      POST <base>/api/updates/pim-manager/head   { kind: 'code'; ring: <n> }   header X-Invardia-Install-Key
      -> { version; sequence; expedite?: { apply: 'now' | 'window'; until; reason } }
  On expedite.apply = 'now' for a version NEWER than the installed one, it starts the updater job (ca-pim-update) ONCE --
  the same ARM start the updater's own follow-up run uses (Start-PimAcaJobExecution) -- and records why. Everything else
  is left to the nightly run.

  INERT-SAFE (the route is not live yet):
    * 404 = the route does not exist: silent, no effect, at most ONE line a day in the log.
    * every other failure (no network, 5xx, an answer that is not JSON, a start that was refused) = ONE warning, repeated
      only when its text changes or once a day. Nothing here can fail the tick.
    * at most ONE start per VERSION, ever: the version is written to the state BEFORE the start is attempted, so a crash, a
      refused start or a second scheduler instance can never start a second update for it (the nightly run takes it then).
    * never while an update run is already running; when that cannot be read, it does NOT start (and warns once).
    * a local veto: pim.Settings 'UpdateExpediteAllowed' = false / 0 / off / no (default: allowed) -- the check still runs
      and records "vetoed", it starts nothing.
    * off with the telemetry switch (feature 'telemetry.uplink'), without an install key, without a known ring or version.
  State: pim.Settings 'UpdateExpediteState' { lastCheckUtc; lastStatus; lastResult; started: { <version>: <utc> };
  warning; warningUtc; noRouteLogUtc }. REST only, no modules; Windows PowerShell 5.1 + PowerShell 7; ASCII only.
  Seams (tests): -GetSetting / -SetSetting / -Http / -StartJob / -IsRunning / -Warn / -Log / -NowUtc.
#>

function Get-PimUpdateExpediteIntervalMinutes { <# PURE. The cadence of the check -- a literal (child-scope safe). #> return 15 }

function Compare-PimExpediteVersion {
    <#
      PURE. 1 when -A is newer than -B, -1 when older, 0 when the same -- by the numeric parts ('2.4.611' vs '2.4.99').
      $null when either is not a dotted number (a version that cannot be read is never "newer").
    #>
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

function Test-PimUpdateExpediteAllowed {
    <# PURE. The local veto: allowed unless the stored value is false / 0 / off / no (a bool $false too). Nothing stored = allowed. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return [bool]$Value }
    return -not [bool]("$Value".Trim().Trim('"') -match '^(?i)(0|false|off|no)$')
}

function Get-PimUpdateExpediteField {
    # PURE. A property of an object or a dictionary, $null when absent.
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimUpdateExpediteUtc {
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

function Get-PimUpdateExpediteDecision {
    <#
      PURE. What to do with Invardia's answer: @{ action; version; reason }.
        action 'start'   expedite.apply = 'now', the head's version is NEWER than the installed one, 'until' has not passed,
                         the veto is not set and no start was made for that version before
               'none'    everything else, with the reason in words (no mark / apply 'window' / same or older version /
                         the mark ran out / vetoed / already started / an answer that cannot be read)
      -Head       the parsed answer { version; sequence; expedite? }
      -Started    the versions a start was already made for (a dictionary / object: version -> time)
    #>
    param([AllowNull()][object]$Head, [string]$InstalledVersion = '', [bool]$Allowed = $true, [AllowNull()][object]$Started = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $none = { param($why, $ver) return [pscustomobject]@{ action = 'none'; version = "$ver"; reason = "$why" } }
    if ($null -eq $Head) { return (& $none 'the answer could not be read' '') }
    $ver = "$(Get-PimUpdateExpediteField $Head 'version')".Trim()
    $ex = Get-PimUpdateExpediteField $Head 'expedite'
    if ($null -eq $ex) { return (& $none 'no expedite mark on the head of this ring' $ver) }
    $apply = "$(Get-PimUpdateExpediteField $ex 'apply')".Trim().ToLowerInvariant()
    if ($apply -eq 'window') { return (& $none 'expedite within the agreed hours: the scheduled update run takes it' $ver) }
    if ($apply -ne 'now') { return (& $none "an expedite mark with an unknown 'apply' value" $ver) }
    $cmp = Compare-PimExpediteVersion -A $ver -B $InstalledVersion
    if ($null -eq $cmp) { return (& $none 'the version of the head or the installed version cannot be read' $ver) }
    if ($cmp -le 0) { return (& $none "the installed version ($InstalledVersion) is the head ($ver) or newer" $ver) }
    $untilRaw = Get-PimUpdateExpediteField $ex 'until'
    if ($null -ne $untilRaw -and "$untilRaw".Trim()) {
        $until = ConvertTo-PimUpdateExpediteUtc $untilRaw
        if ($null -eq $until) { return (& $none "the expedite mark's 'until' cannot be read" $ver) }
        if ($NowUtc.ToUniversalTime() -gt $until) { return (& $none 'the expedite mark has run out' $ver) }
    }
    if (-not $Allowed) { return (& $none "vetoed here (pim.Settings 'UpdateExpediteAllowed' is off): the scheduled update run takes it" $ver) }
    if ($null -ne (Get-PimUpdateExpediteField $Started $ver)) { return (& $none "an update was already started for $ver by this check" $ver) }
    $why = ("$(Get-PimUpdateExpediteField $ex 'reason')" -replace '\s+', ' ').Trim()
    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    return [pscustomobject]@{ action = 'start'; version = $ver; reason = $(if ($why) { $why } else { 'no reason given' }) }
}

function Invoke-PimUpdateExpediteCheck {
    <#
      ONE check, every seam injected (the file header has the rules). Returns
        @{ checked; due; status; started; version; action; detail; warning }
      and never throws. checked = $false when it is off or not due (then nothing was read and nothing was written).
        -Http      { param($Method, $Url, $Body, $Headers) } -> @{ status = <int>; body = <object or JSON text> }
        -StartJob  { } -> @{ ok; execution; reason }           -IsRunning { } -> $true | $false | $null (cannot be read)
        -Warn      { param($Message) }   (the caller dedupes nothing: this function decides when a warning is due)
        -Log       { param($Message) }   (quiet lines: the once-a-day "no route" line, the start)
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting, [Parameter(Mandatory)][scriptblock]$Http,
          [Parameter(Mandatory)][scriptblock]$StartJob, [scriptblock]$IsRunning = $null, [scriptblock]$Warn = $null, [scriptblock]$Log = $null,
          [bool]$Enabled = $false, [string]$InstallKey = '', [string]$InstalledVersion = '', [AllowNull()][object]$Ring = $null,
          [string]$Product = 'pim-manager', [string]$BaseUrl = 'https://invardia.com', [datetime]$NowUtc = [datetime]::UtcNow)
    $res = [ordered]@{ checked = $false; due = $false; status = 0; started = $false; version = ''; action = 'none'; detail = ''; warning = '' }
    try {
        $NowUtc = $NowUtc.ToUniversalTime()
        if (-not $Enabled) { $res.detail = 'off (telemetry is switched off)'; return [pscustomobject]$res }
        $ringNo = 0
        if ($null -eq $Ring -or "$Ring" -eq '' -or -not [int]::TryParse("$Ring", [ref]$ringNo) -or $ringNo -lt 0 -or $ringNo -gt 10) { $res.detail = 'off (the update ring of this environment is not known)'; return [pscustomobject]$res }
        if ($null -eq (Compare-PimExpediteVersion -A $InstalledVersion -B $InstalledVersion)) { $res.detail = 'off (the installed version is not known)'; return [pscustomobject]$res }
        if (-not "$InstallKey".Trim()) { $res.detail = 'off (no install key: updates do not come from Invardia here)'; return [pscustomobject]$res }
        $base = "$BaseUrl".Trim().TrimEnd('/')
        if ($base -notmatch '^(?i)https://') { $res.detail = 'off (the update address is not https)'; return [pscustomobject]$res }

        $st = $null; try { $st = & $GetSetting 'UpdateExpediteState' } catch { $st = $null }
        for ($i = 0; $i -lt 2 -and $st -is [string]; $i++) { $t0 = "$st".Trim(); if ($t0.StartsWith('{')) { try { $st = $t0 | ConvertFrom-Json } catch { $st = $null } } else { $st = $null } }
        $last = ConvertTo-PimUpdateExpediteUtc (Get-PimUpdateExpediteField $st 'lastCheckUtc')
        $every = 15   # minutes, literal (Get-PimUpdateExpediteIntervalMinutes)
        if ($last -and $NowUtc -lt $last.AddMinutes($every) -and $NowUtc -ge $last.AddMinutes(-1)) { $res.detail = 'not due'; return [pscustomobject]$res }
        $res.due = $true

        $started = [ordered]@{}
        $so = Get-PimUpdateExpediteField $st 'started'
        if ($so -is [System.Collections.IDictionary]) { foreach ($k in @($so.Keys)) { $started["$k"] = "$($so[$k])" } }
        elseif ($null -ne $so) { foreach ($p in $so.PSObject.Properties) { $started["$($p.Name)"] = "$($p.Value)" } }
        $prevWarn = "$(Get-PimUpdateExpediteField $st 'warning')"; $prevWarnUtc = ConvertTo-PimUpdateExpediteUtc (Get-PimUpdateExpediteField $st 'warningUtc')
        $noRouteLog = ConvertTo-PimUpdateExpediteUtc (Get-PimUpdateExpediteField $st 'noRouteLogUtc')
        # a hashtable, so the two scriptblocks below change it by reference (no scope tricks)
        $ws = @{ warn = ''; warnUtc = $prevWarnUtc; noRoute = $noRouteLog }
        # ONE deduplicated warning: said when its text changes, or again after a day.
        $warnOnce = {
            param($m)
            $res.warning = "$m"
            if ("$m" -ne $prevWarn -or -not $prevWarnUtc -or ($NowUtc - $prevWarnUtc).TotalHours -ge 24) {
                $ws.warnUtc = $NowUtc
                if ($Warn) { & $Warn "[update-expedite] $m" } else { Write-Warning "[update-expedite] $m" }
            }
            $ws.warn = "$m"
        }
        $save = {
            $keep = [ordered]@{}
            foreach ($k in @(@($started.Keys) | Select-Object -Last 20)) { $keep["$k"] = "$($started[$k])" }
            $o = [ordered]@{ lastCheckUtc = $NowUtc.ToString('o'); lastStatus = [int]$res.status; lastResult = "$($res.detail)"; started = [pscustomobject]$keep
                             warning = "$($ws.warn)"; warningUtc = $(if ($ws.warn -and $ws.warnUtc) { ([datetime]$ws.warnUtc).ToString('o') } else { '' })
                             noRouteLogUtc = $(if ($ws.noRoute) { ([datetime]$ws.noRoute).ToString('o') } else { '' }) }
            try { & $SetSetting 'UpdateExpediteState' ([pscustomobject]$o); return $true } catch { return $false }
        }

        $res.checked = $true
        $url = "$base/api/updates/$("$Product".Trim().ToLowerInvariant())/head"
        $ans = $null; $httpErr = ''
        try { $ans = & $Http 'POST' $url ([ordered]@{ kind = 'code'; ring = $ringNo }) @{ 'X-Invardia-Install-Key' = "$InstallKey" } } catch { $httpErr = (("$($_.Exception.Message)") -split "`n")[0] }
        $code = 0; try { $code = [int](Get-PimUpdateExpediteField $ans 'status') } catch { $code = 0 }
        $res.status = $code
        if ($code -eq 404) {
            # The route is not live (or not for this product): silent. At most one line a day, never a warning.
            $res.detail = 'Invardia has no expedite route yet (404) -- nothing to do'
            if (-not $noRouteLog -or ($NowUtc - $noRouteLog).TotalHours -ge 24) { $ws.noRoute = $NowUtc; if ($Log) { & $Log "[update-expedite] $($res.detail)" } }
            [void](& $save); return [pscustomobject]$res
        }
        if ($code -ne 200) {
            $res.detail = $(if ($httpErr) { "the expedite check could not reach Invardia: $httpErr" } else { "the expedite check was answered HTTP $code" })
            & $warnOnce $res.detail
            [void](& $save); return [pscustomobject]$res
        }
        $head = Get-PimUpdateExpediteField $ans 'body'
        if ($head -is [string]) { try { $head = $head | ConvertFrom-Json -ErrorAction Stop } catch { $head = $null } }
        if ($null -eq $head -or -not "$(Get-PimUpdateExpediteField $head 'version')".Trim()) {
            $res.detail = 'the expedite check was answered without a version'
            & $warnOnce $res.detail
            [void](& $save); return [pscustomobject]$res
        }
        $allowed = $true; try { $allowed = Test-PimUpdateExpediteAllowed (& $GetSetting 'UpdateExpediteAllowed') } catch { $allowed = $true }
        $d = Get-PimUpdateExpediteDecision -Head $head -InstalledVersion $InstalledVersion -Allowed $allowed -Started $started -NowUtc $NowUtc
        $res.version = "$($d.version)"; $res.detail = "$($d.reason)"
        if ("$($d.action)" -ne 'start') { [void](& $save); return [pscustomobject]$res }

        # A run already running? $true = wait for it (the version is NOT marked: the next check looks again -- that run may be
        # the one that installs it). Cannot be read = do not start.
        $running = $null
        if ($IsRunning) { try { $running = & $IsRunning } catch { $running = $null } }
        if ($running -is [bool] -and $running) { $res.detail = "expedite for $($d.version): an update run is already running -- not started"; [void](& $save); return [pscustomobject]$res }
        if (-not ($running -is [bool])) {
            $res.detail = "expedite for $($d.version): whether an update run is running could not be read -- not started (the scheduled run takes it)"
            & $warnOnce $res.detail
            [void](& $save); return [pscustomobject]$res
        }
        # Mark FIRST, start second: never more than one start per version, whatever happens next.
        $started["$($d.version)"] = $NowUtc.ToString('o')
        $res.detail = "expedite for $($d.version): starting the update job ($($d.reason))"
        if (-not (& $save)) {
            $res.detail = "expedite for $($d.version): the start could not be recorded -- not started (the scheduled run takes it)"
            & $warnOnce $res.detail
            return [pscustomobject]$res
        }
        $sj = $null; try { $sj = & $StartJob } catch { $sj = @{ ok = $false; reason = (("$($_.Exception.Message)") -split "`n")[0] } }
        if ($sj -and [bool](Get-PimUpdateExpediteField $sj 'ok')) {
            $res.started = $true; $res.action = 'start'
            $res.detail = "expedite: the update job was started for $($d.version) (installed $InstalledVersion) -- $($d.reason)"
            if ($Log) { & $Log "[update-expedite] $($res.detail)" }
        } else {
            $res.detail = "expedite for $($d.version): the update job could not be started ($("$(Get-PimUpdateExpediteField $sj 'reason')".Trim())) -- the scheduled run takes it"
            & $warnOnce $res.detail
        }
        [void](& $save)
        return [pscustomobject]$res
    } catch {
        $res.detail = "the expedite check failed: $((("$($_.Exception.Message)") -split "`n")[0])"
        $res.warning = $res.detail
        return [pscustomobject]$res
    }
}

function Invoke-PimUpdateExpediteHttp {
    <# The default -Http: one POST with a JSON body, 15 s, never throws: @{ status; body }. A 404 is a status, not an error. #>
    param([string]$Method, [string]$Url, [AllowNull()][object]$Body, [hashtable]$Headers = @{})
    try {
        $json = if ($null -ne $Body) { ConvertTo-Json -InputObject $Body -Depth 5 -Compress } else { '{}' }
        $r = Invoke-WebRequest -Uri $Url -Method $Method -Body $json -ContentType 'application/json' -Headers $Headers -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        return @{ status = [int]$r.StatusCode; body = "$($r.Content)" }
    } catch {
        $code = 0
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        if ($code -gt 0) { return @{ status = $code; body = $null } }
        throw
    }
}

function Test-PimUpdateJobRunning {
    <#
      Is an execution of the update job running right now? $true / $false, or $null when it cannot be read (no ARM helper,
      no permission, an error) -- the caller then does not start. -List { } -> the executions (test seam).
    #>
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$JobName = 'ca-pim-update', [scriptblock]$List = $null)
    try {
        $items = $null
        if ($List) { $items = @(& $List) }
        else {
            if (-not "$SubscriptionId".Trim() -or -not "$ResourceGroup".Trim() -or -not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) { return $null }
            $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName/executions"
            $resp = Invoke-PimArm -Method GET -Path $path -ApiVersion '2024-03-01'
            if ($null -eq $resp) { return $false }
            $items = @(if ($resp.PSObject.Properties['value']) { $resp.value } else { $resp })
        }
        foreach ($x in @($items | Where-Object { $null -ne $_ })) {
            $s = ''
            if ($x.PSObject.Properties['properties'] -and $x.properties -and $x.properties.PSObject.Properties['status']) { $s = "$($x.properties.status)" }
            elseif ($x.PSObject.Properties['status']) { $s = "$($x.status)" }
            if ($s -match '^(?i)(Running|Processing|Unknown)$') { return $true }
        }
        return $false
    } catch { return $null }
}

function Invoke-PimUpdateExpediteTickStep {
    <#
      The scheduler's per-tick call (main instance, not -WhatIf). Cheap: when the check is not due it reads ONE setting and
      returns. Returns a tick result ONLY when an update was started (a real event); $null otherwise. Never throws.
      Bound to the environment here: the settings store, the installed VERSION, the ring (PIM_UPDATE_RING, else the
      environment's own UpdateState), the install key, feature 'telemetry.uplink', the update job (PIM_SubscriptionId /
      PIM_ResourceGroup / PIM_UpdateJobName). -Check { } is the test seam.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Check = $null)
    try {
        $r = $null
        if ($Check) { $r = & $Check }
        else {
            if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) -or -not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return $null }
            $on = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.uplink' -Quiet))
            if (-not $on) { return $null }
            $sub = "$($env:PIM_SubscriptionId)".Trim(); $rg = "$($env:PIM_ResourceGroup)".Trim()
            if (-not $sub -or -not $rg -or -not (Get-Command Start-PimAcaJobExecution -ErrorAction SilentlyContinue)) { return $null }
            # CR5 step 1 (PIM 100.149): the install record (incl. PIM_UpdateJobName); today's name is the default
            $job = 'ca-pim-update'; if (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { $job = Get-PimInstallName -Role updater } elseif ("$($env:PIM_UpdateJobName)".Trim()) { $job = "$($env:PIM_UpdateJobName)".Trim() }
            $get = { param($n) Get-PimSetting -Name $n }
            $set = { param($n, $v) Set-PimSetting -Name $n -Value (ConvertTo-Json -InputObject $v -Depth 6 -Compress) }
            $key = ''
            if (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue) { try { $key = "$(Resolve-PimInvardiaInstallKey -GetSetting $get)" } catch { $key = '' } } else { $key = "$env:PIM_UPLINK_KEY" }
            $us = $null; try { $us = & $get 'UpdateState'; if ($us -is [string] -and "$us".Trim()) { $us = $us | ConvertFrom-Json } } catch { $us = $null }
            $ring = $null
            if (Get-Command Resolve-PimUplinkRing -ErrorAction SilentlyContinue) { $ring = Resolve-PimUplinkRing -EnvRing "$env:PIM_UPDATE_RING" -UpdateState $us }
            $ver = ''
            $verFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'
            if (Test-Path -LiteralPath $verFile) { $ver = "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } elseif ($env:PIM_VERSION) { $ver = "$env:PIM_VERSION".Trim() }
            $base = 'https://invardia.com'
            if (Get-Command Resolve-PimEnrollmentBaseUrl -ErrorAction SilentlyContinue) { try { $b0 = "$(Resolve-PimEnrollmentBaseUrl -BaseUrl '')".Trim(); if ($b0 -match '^(?i)https://') { $base = $b0 } } catch { } }
            $lo = { param($m) if (Get-Command Write-PimLogOnce -ErrorAction SilentlyContinue) { Write-PimLogOnce -Key 'sched.update-expedite' -Message $m -ForegroundColor DarkGray } else { Write-Host $m -ForegroundColor DarkGray } }
            $r = Invoke-PimUpdateExpediteCheck -GetSetting $get -SetSetting $set -Enabled $on -InstallKey $key -InstalledVersion $ver -Ring $ring -BaseUrl $base -NowUtc $NowUtc `
                    -Http { param($m, $u, $b, $h) Invoke-PimUpdateExpediteHttp -Method $m -Url $u -Body $b -Headers $h } `
                    -StartJob { Start-PimAcaJobExecution -SubscriptionId $sub -ResourceGroup $rg -Name $job -Waits @(0) } `
                    -IsRunning { Test-PimUpdateJobRunning -SubscriptionId $sub -ResourceGroup $rg -JobName $job } `
                    -Warn { param($m) Write-Warning $m } -Log $lo
        }
        if ($r -and [bool]$r.started) { return [pscustomobject]@{ name = 'update-expedite'; type = 'update-expedite'; ok = $true; ran = $true; detail = "$($r.detail)" } }
        return $null
    } catch { return $null }
}
