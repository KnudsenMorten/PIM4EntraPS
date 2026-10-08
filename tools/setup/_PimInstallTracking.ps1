#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS §99 "Support-app installs report their steps to Invardia" (owner via Invardia 2026-10-08: "where are all
  my pim installations") -- the install-step tracking the Support-app runners (Invoke-PimMspBuild, Invoke-PimDeployAll)
  post to Invardia, and the helper that opens a tracked install. Offline-tested in tests/Test-PimInstallVerify.ps1.

.DESCRIPTION
  Contract (Invardia, live 2026-10-08):
    open   POST {base}/api/admin/support-environments/<environmentId>/installations   (platform / staff identity bearer)
           {"productId":"pim-manager","version":"<x>"}  ->  { installationId, token, eventsUrl, statusUrl }
    event  POST {eventsUrl}  (default https://invardia.com/api/install/events), header X-Invardia-Install-Token: <token>
           {"seq":N,"step":{"id","title"},"state":"started|ok|warning|failed|skipped|waiting|completed","at":"<ISO UTC>",
            "durationMs":<ms>,"message":"<one plain line>"}
    done   {"seq":N,"step":{"id":"done"},"state":"completed","outputs":{}}   (or the failed step is the last event)

  🔒 BEST EFFORT. A tracking POST that fails NEVER fails the install: one warning, then the tracker stops posting.
  🔒 NO SECRETS. Every message is one plain line and is scrubbed (bearer tokens, JWTs, install / enrollment keys, SAS
     query strings, key=value secrets) before it leaves; the token itself is only ever a header.
  The guided (trial) install does NOT use this: Invardia's bootstrap passes -Reporter and posts the events itself.
#>

$script:PimInstallEventsDefaultUrl = 'https://invardia.com/api/install/events'

function Protect-PimInstallTrackMessage {
    <# PURE. One plain line, at most 400 characters, with anything credential-shaped replaced by '***'. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text" -replace "[\r\n\t]+", ' '
    $t = $t -replace '(?i)\bBearer\s+[A-Za-z0-9\-\._~\+/]+=*', 'Bearer ***'
    $t = $t -replace '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*)?', '***'                 # JWT
    $t = $t -replace '\b(inv|ek)-[A-Za-z0-9_-]{12,}', '$1-***'                                              # install / enrollment keys
    $t = $t -replace '(?i)([?&](sig|se|sp|sv|st|skoid|sktid|skt|ske|sks|skv|sr|spr)=)[^&\s]+', '$1***'    # SAS
    $t = $t -replace '(?i)\b(password|passwd|pwd|secret|clientsecret|client_secret|apikey|api_key|token|accountkey|sharedaccesskey)(\s*[=:]\s*)("[^"]*"|''[^'']*''|\S+)', '$1$2***'
    $t = ($t -replace '\s{2,}', ' ').Trim()
    if ($t.Length -gt 400) { $t = $t.Substring(0, 400) + ' ...' }
    return $t
}

function New-PimInstallTracker {
    <#
      A tracker for one install. -Token empty = an inert tracker: every call is a no-op. (The RUNNERS resolve $env:INVARDIA_INSTALL_TOKEN
      when their -InvardiaInstallToken is not passed; an explicit empty token -- the guided install, the MSP hosting step -- stays inert.)
      -Http: TEST seam param($method, $url, $headers, $bodyJson) -> anything; throws on failure. Default Invoke-RestMethod.
      -Clock: TEST seam returning [datetime] UTC.
    #>
    param([string]$Token = '', [string]$EventsUrl = '', [scriptblock]$Http, [scriptblock]$Clock)
    $tok = "$Token".Trim()
    $url = "$EventsUrl".Trim(); if (-not $url) { $url = $script:PimInstallEventsDefaultUrl }
    $enabled = [bool]$tok
    if ($enabled -and $url -notmatch '^https://[^\s/?#]+(/[^\s?#]*)?$') { Write-Warning "install tracking OFF: the events address is not a plain https URL"; $enabled = $false }
    if (-not $Http) { $Http = { param($m, $u, $h, $b) Invoke-RestMethod -Method $m -Uri $u -Headers $h -Body $b -ContentType 'application/json' -TimeoutSec 20 } }
    if (-not $Clock) { $Clock = { [datetime]::UtcNow } }
    return [pscustomobject]@{ enabled = $enabled; token = $tok; url = $url; seq = 0; http = $Http; clock = $Clock; stopped = $false; failures = 0; started = @{}; sent = 0 }
}

function Send-PimInstallTrackEvent {
    <#
      Post one step event. Never throws. 'started' records the time; the next state of the same step carries durationMs.
      -Outputs only on the final 'done' event. Returns $true when it was posted.
    #>
    param([Parameter(Mandatory)][object]$Tracker, [Parameter(Mandatory)][string]$StepId, [string]$Title = '',
          [Parameter(Mandatory)][ValidateSet('started', 'ok', 'warning', 'failed', 'skipped', 'waiting', 'completed')][string]$State,
          [string]$Message = '', [System.Collections.IDictionary]$Outputs)
    if (-not $Tracker -or -not $Tracker.enabled -or $Tracker.stopped) { return $false }
    try {
        $now = [datetime](& $Tracker.clock)
        $Tracker.seq = [int]$Tracker.seq + 1
        $step = [ordered]@{ id = $StepId }
        if ("$Title".Trim()) { $step['title'] = (Protect-PimInstallTrackMessage $Title) }
        $ev = [ordered]@{ seq = $Tracker.seq; step = $step; state = $State; at = $now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
        if ($State -eq 'started') { $Tracker.started[$StepId] = $now }
        elseif ($Tracker.started.ContainsKey($StepId)) { $ev['durationMs'] = [int64][Math]::Max(0, ($now - [datetime]$Tracker.started[$StepId]).TotalMilliseconds) }
        $msg = Protect-PimInstallTrackMessage $Message
        if ($msg) { $ev['message'] = $msg }
        if ($null -ne $Outputs) { $o = [ordered]@{}; foreach ($k in $Outputs.Keys) { $o["$k"] = (Protect-PimInstallTrackMessage "$($Outputs[$k])") }; $ev['outputs'] = $o }
        $body = $ev | ConvertTo-Json -Depth 6 -Compress
        & $Tracker.http 'POST' $Tracker.url @{ 'X-Invardia-Install-Token' = $Tracker.token } $body | Out-Null
        $Tracker.sent = [int]$Tracker.sent + 1
        return $true
    } catch {
        # One warning, then silence: reporting must never be why an install fails or slows down.
        $Tracker.failures = [int]$Tracker.failures + 1
        $Tracker.stopped = $true
        Write-Warning ("install tracking to Invardia stopped after a failed post ($((Protect-PimInstallTrackMessage "$($_.Exception.Message)"))) -- the install continues; Invardia's Installations page will show it as incomplete")
        return $false
    }
}

function Complete-PimInstallTracker {
    <# The final event: {step:{id:'done'}, state:'completed', outputs:{...}}. Not sent after a failure (the failed step is the last event). #>
    param([Parameter(Mandatory)][object]$Tracker, [System.Collections.IDictionary]$Outputs = @{}, [switch]$Failed)
    if ($Failed) { return $false }
    return (Send-PimInstallTrackEvent -Tracker $Tracker -StepId 'done' -State completed -Outputs $Outputs)
}

function Open-PimInvardiaTrackedInstall {
    <#
      Open a tracked install at Invardia (ops and the guided path; the RUNNER only posts). -AccessToken: the platform / staff
      identity's bearer for Invardia (never printed). Returns @{ ok; installationId; token; eventsUrl; statusUrl; reason }.
      -Http: TEST seam param($method, $url, $headers, $bodyJson) -> the parsed response.
    #>
    param([Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$AccessToken,
          [string]$BaseUrl = 'https://invardia.com', [string]$ProductId = 'pim-manager', [scriptblock]$Http)
    $base = "$BaseUrl".Trim().TrimEnd('/'); if (-not $base) { $base = 'https://invardia.com' }
    if ($base -notmatch '^https://[^\s/?#]+$') { return @{ ok = $false; reason = 'the Invardia address must be a plain https origin' } }
    if ("$EnvironmentId".Trim() -notmatch '^[A-Za-z0-9._-]{1,128}$') { return @{ ok = $false; reason = 'the environment id is not a plain id' } }
    if (-not $Http) { $Http = { param($m, $u, $h, $b) Invoke-RestMethod -Method $m -Uri $u -Headers $h -Body $b -ContentType 'application/json' -TimeoutSec 30 } }
    $url = "$base/api/admin/support-environments/$([uri]::EscapeDataString("$EnvironmentId".Trim()))/installations"
    $body = [ordered]@{ productId = $ProductId; version = "$Version".Trim() } | ConvertTo-Json -Compress
    try { $r = & $Http 'POST' $url @{ Authorization = "Bearer $AccessToken" } $body }
    catch { return @{ ok = $false; reason = "Invardia refused to open the tracked install: $(Protect-PimInstallTrackMessage "$($_.Exception.Message)")" } }
    $get = { param($n) if ($r -is [System.Collections.IDictionary]) { "$($r[$n])" } elseif ($r -and $r.PSObject.Properties[$n]) { "$($r.$n)" } else { '' } }
    $tok = & $get 'token'
    if (-not $tok) { return @{ ok = $false; reason = 'Invardia answered without an install token' } }
    $ev = & $get 'eventsUrl'; if (-not $ev) { $ev = $script:PimInstallEventsDefaultUrl }
    return @{ ok = $true; installationId = (& $get 'installationId'); token = $tok; eventsUrl = $ev; statusUrl = (& $get 'statusUrl'); reason = '' }
}
