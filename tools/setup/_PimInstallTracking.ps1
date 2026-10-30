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

# ================================================================== hosting SUB-STEP progress (2026-10-11, setup-polish lane)
# The multi-tenant build (Invoke-PimMspBuild) runs its 'hosting' step -- Invoke-PimDeployAll, 10-40 minutes -- in a CHILD
# process, so the deploy's own step events (-OnStep / its tracker) never reached the build's reporter: the tracked install
# showed 'hosting started' and then minutes of silence (a test tenant managed install 2026-10-10). The child now writes ONE marker
# line per deploy step event on its console when the build asks for it ($env:PIM_SUBSTEP_EVENTS = '1', set by the build for
# the step process only); the build reads its step's output as it streams, turns each marker into a step event with the
# id '<parent>.<sub-step>' and relays it exactly like its own steps (Invardia install tracking + -OnStep -> the guided
# install's -Reporter). Same event schema ({seq, step{id,title}, state, message}); a marker line is never echoed.
#
# STABLE SUB-STEP IDS of the hosting step (= Invoke-PimDeployAll's step keys, engine/_shared/PIM-DeployAll.ps1), reported as
# 'hosting.<id>': enroll, prereq, image, infra, sqlaccess, schema, mailsender, features, licence, easyauth, code, updater,
# access, alerting, verify, verify-install. 'appreg' is never shown (a build runs on managed identities). A key outside
# [a-z0-9-] is dropped, never relayed.
$script:PimSubStepLinePrefix = '##pim-substep '

function Get-PimHostingSubStepCatalog {
    <# PURE. The hosting step's stable sub-step ids -> customer-language titles (documented above; DESIGN "Install progress"). #>
    return [ordered]@{
        'enroll'         = 'Link to your Invardia account'
        'prereq'         = 'Network, registry, identity and database'
        'image'          = 'Container image'
        'infra'          = 'Container Apps environment and apps'
        'sqlaccess'      = 'Database access'
        'schema'         = 'Database schema'
        'mailsender'     = 'Notification mailbox'
        'features'       = 'Feature settings'
        'licence'        = 'Your licence'
        'easyauth'       = 'Sign-in for the PIM Manager'
        'code'           = 'Roll out the application'
        'updater'        = 'Updates'
        'access'         = 'PIM Manager access'
        'alerting'       = 'Alert recipients'
        'verify'         = 'Deployment health check'
        'verify-install' = 'End-of-install check'
    }
}

function Format-PimSubStepEventLine {
    <# PURE. One deploy step event -> the marker line the child writes (one line, JSON; nothing secret goes in: scrubbed). #>
    param([Parameter(Mandatory)][string]$Key, [string]$Name = '', [Parameter(Mandatory)][string]$State, [string]$Detail = '')
    $o = [ordered]@{ key = "$Key".Trim(); name = (Protect-PimInstallTrackMessage $Name); state = "$State".Trim(); detail = (Protect-PimInstallTrackMessage $Detail) }
    return ($script:PimSubStepLinePrefix + ($o | ConvertTo-Json -Compress))
}

function ConvertFrom-PimSubStepEventLine {
    <#
      PURE. One console line of a step process -> $null (not a marker, or a malformed / unknown-state / bad-key marker) or
      { StepId = '<ParentStepId>.<key>'; Title = '<ParentTitle>: <sub-step title>'; State; Message (scrubbed, one line) }.
      'appreg' is dropped (never shown). States: started | ok | warning | failed | skipped | waiting.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Line, [Parameter(Mandatory)][string]$ParentStepId, [string]$ParentTitle = '')
    $l = "$Line"
    $ix = $l.IndexOf($script:PimSubStepLinePrefix.Trim(), [StringComparison]::Ordinal)
    if ($ix -lt 0) { return $null }
    $json = $l.Substring($ix + $script:PimSubStepLinePrefix.Trim().Length).Trim()
    $o = $null; try { $o = $json | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
    if ($null -eq $o) { return $null }
    $key = "$($o.key)".Trim().ToLowerInvariant(); $state = "$($o.state)".Trim().ToLowerInvariant()
    if ($key -notmatch '^[a-z0-9][a-z0-9-]{0,39}$' -or $key -eq 'appreg') { return $null }
    if ($state -notin @('started', 'ok', 'warning', 'failed', 'skipped', 'waiting')) { return $null }
    $cat = Get-PimHostingSubStepCatalog
    $sub = if ($cat.Contains($key)) { $cat[$key] } elseif ("$($o.name)".Trim()) { "$($o.name)".Trim() } else { $key }
    $title = if ("$ParentTitle".Trim()) { "$("$ParentTitle".Trim()): $sub" } else { $sub }
    return [pscustomobject]@{ StepId = "$("$ParentStepId".Trim()).$key"; Title = (Protect-PimInstallTrackMessage $title); State = $state; Message = (Protect-PimInstallTrackMessage "$($o.detail)") }
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
