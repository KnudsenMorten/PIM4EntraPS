#Requires -Version 5.1
<#
.SYNOPSIS
  §95.3 -- PIM's status telemetry (job 'uplink'): a daily HEARTBEAT and one RUN report per job that ran, sent to the
  Invardia-hosted uplink through the FRAMEWORK client (sync/_AitUplink.ps1 Schema 2; a byte-identical copy ships as
  engine/_shared/AitUplink.framework.ps1 because sync/ is never in the container -- Test-PimUplink pins the copy).
  Contract: Invardia docs/design/TELEMETRY-UPLINK.md (owner decisions 2026-10-03); framework DOCS/REQUIREMENTS.md §8.

.DESCRIPTION
  WHO SENDS WHAT
    * no install key   -> ANONYMOUS: the public community code; no tenant, no host, no error text; error CLASS and bucketed
                          counts only; a random TelemetryInstallId (its OWN id -- never the licence request's InstallId,
                          which travels next to the tenant id, so the two cannot be joined at Invardia).
    * PIM_UPLINK_KEY   -> IDENTIFIED (Pro / trial): the per-install key Invardia issued, delivered as a Container Apps
                          secret (secretref) -> environment variable. The key proves the environment; the tenant in the
                          body is only compared for mismatch. Error text shortened + redacted before it leaves.
  WHEN
    * heartbeat: once per 24 h. Identified only (PIM 100.36): Counts { sqlUsedMb, sqlMaxMb } -- the store's allocated data
      pages and max size, MB (Get-PimUplinkSqlSpace); a failed / empty read leaves both out, never a 0.
    * run: per job NAME, the newest finished run since the last send; Outcome = failed if ANY run of it failed since,
      warning if one was held, else ok. One report per job per cycle -- never one per run: rfa-sync runs every tick and
      Invardia allows 30 POSTs a minute per IP (shared behind a NAT): at most 20 per cycle, 2.5 s apart,
      the first failure stops the cycle, and each job keeps its own watermark so nothing is skipped or sent twice.
    * skipped / unimplemented / running runs are not reported (nothing ran), and the uplink job never reports itself.
    * setup (PIM 100.10, framework 8.7): identified only, feature 'telemetry.setup', daily + on every change -- the control
      list, permission counts (+ Get Started steps / findings with PIM_UPLINK_SETUP_EXTENDED=1). PIM-UplinkSetup.ps1.
    * every record carries Ring: PIM_UPDATE_RING, else the ring recorded in pim.Settings['UpdateState'] (Resolve-PimUplinkRing).
  🔒 OFF until the feature 'telemetry.uplink' is switched on. The owner decided "ON by default" for Community
     (2026-10-03, relayed in Invardia's design doc); PIM ships it OFF until the operator confirms it in the PIM session,
     exactly like 'licence.autoRequest' -- a decision relayed by another session is not that confirmation.
  🔒 A failed send never fails anything else: the job reports it in its detail, keeps its watermark (the runs are sent
     on the next cycle), and the next heartbeat is not skipped.
#>

$script:PimUplinkProduct = 'pim-manager'
# Invardia's limit (2026-10-04): 30 POSTs per MINUTE per client IP -- and several installs behind one NAT share it. So at most
# 20 reports per cycle, ~2.5 s apart (the job passes -PauseMs 2500), and the cycle STOPS at the first failure (a 429 says
# wait): what was not sent keeps its per-job watermark and goes next cycle.
$script:PimUplinkMaxRunsPerCycle = 20

function Get-PimUplinkJobId {
    <# PURE. The stable Job id Invardia stores: 'pim-' + the job TYPE (one-off trigger names collapse onto their type). #>
    param([AllowNull()][object]$Run)
    $t = "$($Run.type)".Trim().ToLowerInvariant()
    if (-not $t) { $t = "$($Run.name)".Trim().ToLowerInvariant() }
    $t = ($t -replace '[^a-z0-9.-]', '-').Trim('-')
    if (-not $t) { return '' }
    return "pim-$t"
}

function Get-PimUplinkRunOutcome {
    <# PURE. ok | warning | failed | '' (not reportable: skipped, unimplemented, still running, nothing ran). #>
    param([AllowNull()][object]$Run)
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    if ($st -in @('running', 'skipped', 'unimplemented', 'outofscope', 'disabled', '')) { return '' }
    # §95.2o: an INTERRUPTED run (the scheduler restarted for an update, the platform stopped the execution) is not a
    # product failure -- reported as a warning, never as a failed run (Invardia fix request d0217f96).
    if ($st -eq 'interrupted') { return 'warning' }
    if ($st -eq 'failed' -or ($Run.PSObject.Properties['ok'] -and -not [bool]$Run.ok)) { return 'failed' }
    if ($Run.PSObject.Properties['held'] -and [bool]$Run.held) { return 'warning' }
    if ($st -eq 'held') { return 'warning' }
    return 'ok'
}

function Get-PimUplinkRunPlan {
    <#
      PURE. From the job run history (any order) and the watermarks, ALL run reports due, failures first, then oldest first:
      @{ reports = @( @{ job; outcome; durationMs; errorText; finishedUtc; runCount } ); watermarkUtc = <newest finishedUtc seen> }
      A run counts when it FINISHED after its job's own watermark (-SinceByJob['pim-<type>']), else after -SinceUtc.
      ONE WATERMARK PER JOB, not one for all: a cycle may send only some reports (the rate limit), and a single watermark
      would then skip the jobs that were not sent. The 'uplink' job itself is left out (it would report itself forever).
    #>
    param([object[]]$Runs = @(), [AllowNull()][object]$SinceUtc, [hashtable]$SinceByJob = @{})
    $since = $null; try { if ($SinceUtc) { $since = ([datetime]$SinceUtc).ToUniversalTime() } } catch { $since = $null }
    $byJob = [ordered]@{}
    $newest = $since
    foreach ($r in @($Runs | Where-Object { $_ })) {
        $fin = $null; try { if ("$($r.finishedUtc)") { $fin = ([datetime]"$($r.finishedUtc)").ToUniversalTime() } } catch { $fin = $null }
        if (-not $fin) { continue }
        $job = Get-PimUplinkJobId -Run $r
        if (-not $job -or $job -eq 'pim-uplink') { continue }
        $js = $since
        if ($SinceByJob -and $SinceByJob.ContainsKey($job)) { try { $js = ([datetime]"$($SinceByJob[$job])").ToUniversalTime() } catch { } }
        if ($js -and $fin -le $js) { continue }
        $out = Get-PimUplinkRunOutcome -Run $r
        if (-not $out) { continue }
        if (-not $newest -or $fin -gt $newest) { $newest = $fin }
        if (-not $byJob.Contains($job)) { $byJob[$job] = @{ job = $job; latest = $r; latestFin = $fin; failed = $null; held = $false; count = 0 } }
        $e = $byJob[$job]; $e.count++
        if ($fin -gt $e.latestFin) { $e.latest = $r; $e.latestFin = $fin }
        if ($out -eq 'failed' -and (-not $e.failed -or $fin -gt ([datetime]"$($e.failed.finishedUtc)").ToUniversalTime())) { $e.failed = $r }
        if ($out -eq 'warning') { $e.held = $true }
    }
    $reports = New-Object System.Collections.Generic.List[object]
    # Failures first (they matter most when the rate limit leaves some for the next cycle), then the oldest first.
    $order = @($byJob.Keys | Sort-Object @{ Expression = { if ($byJob[$_].failed) { 0 } else { 1 } } }, @{ Expression = { $byJob[$_].latestFin } }, @{ Expression = { $_ } })
    foreach ($k in $order) {
        $e = $byJob[$k]
        $outcome = if ($e.failed) { 'failed' } elseif ($e.held) { 'warning' } else { 'ok' }
        # A failure is reported WITH the failing run's text, even when a later run of the same job succeeded.
        $src = if ($e.failed) { $e.failed } else { $e.latest }
        $dur = $null; if ($src.PSObject.Properties['durationMs']) { $dur = $src.durationMs }
        $txt = if ($outcome -eq 'failed') { "$($src.detail)" } else { '' }
        [void]$reports.Add(@{ job = $e.job; outcome = $outcome; durationMs = $dur; errorText = $txt; finishedUtc = $e.latestFin.ToString('o'); runCount = $e.count })
    }
    $wm = $null; if ($newest) { $wm = ([datetime]$newest).ToString('o') }
    $arr = $reports.ToArray()
    return @{ reports = $arr; watermarkUtc = $wm }
}

function Get-PimUplinkHeartbeatDue {
    <# PURE. True when no heartbeat was sent in the last 24 h (or ever). #>
    param([AllowNull()][object]$LastHeartbeatUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    try { if ("$LastHeartbeatUtc") { return ($NowUtc.ToUniversalTime() -ge ([datetime]"$LastHeartbeatUtc").ToUniversalTime().AddHours(24)) } } catch { }
    return $true
}

function Get-PimUplinkEdition {
    <# PURE. community | pro | trial, from the licence verdict for THIS tenant (a Pro-Trial sku is 'trial'). #>
    param([AllowNull()][object]$License, [bool]$ProHere)
    if (-not $ProHere) { return 'community' }
    if ("$($License.Sku)".Trim() -match '(?i)trial') { return 'trial' }
    return 'pro'
}

function Get-PimUplinkLicenceState {
    <# PURE. valid | grace | expired | none (Invardia's closed list). #>
    param([AllowNull()][object]$License)
    switch ("$($License.Status)") { 'Valid' { 'valid' } 'Grace' { 'grace' } 'Expired' { 'expired' } default { 'none' } }
}

function Get-PimUplinkErrorClass {
    <#
      The failure catalog code for a failed run's text, lower-cased by the framework. Invardia's ErrorClass list is closed by
      SHAPE ([a-z0-9-]{1,40}, packages/core uplink.ts); the catalog codes are its values.
      🔴 100.34 (Invardia triage 2026-10-09: 11 of 12 PIM fix requests titled "unclassified"). A failed run's text is the
      job SUMMARY (Format-PimFailureSummary: "3 item(s) failed: 2x <title> [WORKLOAD-RESOURCE-MISSING]; 1x ..."), not a raw
      error, so the catalog's raw-error rules matched nothing and every classified failure went up as UNCLASSIFIED. The
      code the engine already put in brackets wins -- the first known one, which is the largest group (the summary is
      sorted by count); UNCLASSIFIED only when the engine itself said so or nothing is known. A convergence verdict is
      CONVERGENCE. Only then is the raw text classified.
    #>
    param([string]$Text)
    if (-not "$Text".Trim()) { return '' }
    $known = @{}
    if (Get-Command Get-PimFailureCatalogCodes -ErrorAction SilentlyContinue) { try { foreach ($c in @(Get-PimFailureCatalogCodes)) { $known["$c"] = $true } } catch { } }
    foreach ($m in [regex]::Matches("$Text", '\[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\]')) {
        $code = $m.Groups[1].Value
        if ($code -ne 'UNCLASSIFIED' -and $known.ContainsKey($code)) { return $code }
    }
    if ("$Text" -match '(?i)CONVERGENCE FAILURE') { return 'CONVERGENCE' }
    if (Get-Command Get-PimFailureClassification -ErrorAction SilentlyContinue) {
        try { $c = "$((Get-PimFailureClassification -Message $Text).code)"; if ($c) { return $c } } catch { }
    }
    return 'UNCLASSIFIED'
}

function Get-PimUplinkFixKind {
    <#
      100.34. customer-config | product-defect for an ErrorClass, from the failure catalog (Get-PimFailureFixKind). Invardia
      raises a fix request only for product defects and shows customer-config items to support. '' for a run with no class.
    #>
    param([string]$ErrorClass)
    $c = "$ErrorClass".Trim(); if (-not $c) { return '' }
    if (Get-Command Get-PimFailureFixKind -ErrorAction SilentlyContinue) { try { return "$(Get-PimFailureFixKind -Code $c)" } catch { } }
    return 'product-defect'
}

function Test-PimUplinkFixKindEnabled {
    <#
      100.34 (Invardia 2026-10-09: the §8.4 run report gets an optional FixKind, absent = product-defect). Invardia's side is
      LIVE (6f2dce4, migration 046: a customer-config report opens NO fix request, it shows as "Needs customer action"), so
      the field is ON by default from 2.4.539; PIM_UPLINK_FIXKIND = 0 / false / off / no switches it off (escape hatch).
      The class itself (ErrorClass) is sent either way.
    #>
    param([AllowNull()][string]$Value = $env:PIM_UPLINK_FIXKIND)
    return -not [bool]("$Value".Trim() -match '^(?i)(0|false|off|no)$')
}

function Get-PimUplinkConsentAction {
    <#
      PURE. Invardia PRO-UPDATE-PLATFORM §11: ONE report when the customer switches telemetry off ('optout'), ONE when it is
      switched on again ('optin'). -State = UplinkState; its 'consent' is the last switch position that was DELIVERED
      ('on' / 'off'). A state written before consent existed, by a cycle that sent, counts as 'on'.
        on  -> off  : 'optout'      off -> on : 'optin'
        never on, off : ''  -- nothing was ever sent, so there is nothing to opt out of (no call to invardia.com at all)
        first time on : ''  -- starting is not an opt-in
    #>
    param([AllowNull()][object]$State, [bool]$Enabled)
    $prev = ''
    if ($State) {
        if ($State.PSObject.Properties['consent'] -and "$($State.consent)".Trim()) { $prev = "$($State.consent)".Trim().ToLowerInvariant() }
        elseif ($State.PSObject.Properties['mode'] -and "$($State.mode)" -in @('anonymous', 'identified')) { $prev = 'on' }
    }
    if ($Enabled -and $prev -eq 'off') { return 'optin' }
    if (-not $Enabled -and $prev -eq 'on') { return 'optout' }
    return ''
}

function New-PimUplinkConsentReport {
    <#
      PURE. The optout / optin record: Schema 2, the Kind and the identity fields only (Product, Version, Ring, and the
      InstallId when anonymous / ClaimedTenantId when identified). Built HERE, not by the framework's New-AitUplinkReport,
      whose Kind list is heartbeat / run / install: sync/ ships to every customer with release discipline, and PIM's copy of
      it must stay byte-identical (Test-PimUplink). Invardia's server lists both kinds (packages/core uplink.ts KINDS).
      $null when an anonymous report has no install id (the server would refuse it).
    #>
    param([Parameter(Mandatory)][ValidateSet('optout', 'optin')][string]$Kind, [Parameter(Mandatory)][ValidateSet('anonymous', 'identified')][string]$Mode,
          [string]$Version = '', [AllowNull()][object]$Ring, [string]$InstallId = '', [string]$TenantId = '', [datetime]$Now = [datetime]::UtcNow)
    $iid = "$InstallId".Trim().ToLowerInvariant()
    if ($Mode -eq 'anonymous' -and $iid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $null }
    $o = [ordered]@{ Schema = 2; Kind = $Kind; Product = $script:PimUplinkProduct }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    if ($Mode -eq 'anonymous') { $o['InstallId'] = $iid } elseif ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() }
    $o['LastSeenUtc'] = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    return [pscustomobject]$o
}

# PIM 100.36 (owner via Invardia 2026-10-09: "telemetry must collect available sql db space remaining in health telemetry"):
# allocated data pages (ROWS files) and the database's max size, both MB. Azure SQL; on a server without a max size
# (MaxSizeInBytes NULL / -1) nothing is reported.
$script:PimUplinkSqlSpaceQuery = @'
SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS bigint) / 1048576 AS maxMb,
       (SELECT SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint)) * 8 / 1024 FROM sys.database_files WHERE type_desc = 'ROWS') AS usedMb
'@

function Get-PimUplinkSqlSpace {
    <#
      PIM 100.36. The heartbeat's SQL space numbers: @{ sqlUsedMb; sqlMaxMb } (integers, MB), or $null. -Query { } runs the SQL
      above and returns its row (the job binds Invoke-PimSqlQuery with the store's MI connection; tests pass a stub). A query
      that throws, returns nothing, or a value that is missing / not a number / not positive (max) = $null: BOTH keys are
      then left out -- never a 0, never a guess. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query)
    try {
        $row = @(& $Query) | Select-Object -First 1
        if ($null -eq $row) { return $null }
        $u = Get-PimUplinkField $row 'usedMb'; $m = Get-PimUplinkField $row 'maxMb'
        $ui = [int64]0; $mi = [int64]0
        if ($null -eq $u -or $null -eq $m -or $u -is [DBNull] -or $m -is [DBNull]) { return $null }
        if (-not [int64]::TryParse("$u", [ref]$ui) -or -not [int64]::TryParse("$m", [ref]$mi)) { return $null }
        if ($ui -lt 0 -or $mi -le 0) { return $null }
        return @{ sqlUsedMb = $ui; sqlMaxMb = $mi }
    } catch { return $null }
}

function Get-PimUplinkField {
    # A property of a PSCustomObject / DataRow-like object or a dictionary, $null when absent (PIM-Uplink.ps1 stands alone).
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Send-PimUplinkRecord {
    <#
      §100.39 (framework §12.6b): the framework's Send-AitUplink, WITH the response body. Send-AitUplink throws the body away
      (`$null = Invoke-RestMethod ...`), and sync/_AitUplink.ps1 ships to every customer with no review step, so it is NOT
      changed: this wrapper calls it unchanged -- same https / credential guards, headers, timeout, never-throw -- and a
      function-local Invoke-RestMethod (PowerShell resolves commands through the caller's scopes; both files are dot-sourced,
      not modules) hands the call to the real cmdlet and keeps what it returned. Returns Send-AitUplink's
      { Status; Reason; Sent } + Body (the parsed JSON response, or $null). Never throws.
      -Transport is a test seam: { <Invoke-RestMethod's arguments> } -> the response. Default = the real cmdlet.
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][string]$Endpoint, [AllowNull()][string]$AccessCode, [scriptblock]$Transport = $null)
    $box = @{ body = $null }
    $xport = if ($Transport) { $Transport } else { { Microsoft.PowerShell.Utility\Invoke-RestMethod @args } }
    function Invoke-RestMethod { $resp = & $xport @args; $box.body = $resp; $resp }
    $r = $null
    try { $r = Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode } catch { $r = [pscustomobject]@{ Status = 'failed'; Reason = "uplink POST failed: $($_.Exception.Message)"; Sent = $false } }
    $o = [ordered]@{ Status = "$($r.Status)"; Reason = "$($r.Reason)"; Sent = [bool]$r.Sent; Body = $null }
    if ("$($r.Status)" -eq 'ok') { $o['Body'] = $box.body }
    return [pscustomobject]$o
}

function Get-PimUplinkSupersededBy {
    <#
      PURE. §100.39 / framework §12.6b: the licence id in a heartbeat response's `supersededBy`, or '' -- an object, a
      dictionary or JSON text; anything malformed (no field, not a string, not an id shape) is ''. Never throws.
    #>
    param([AllowNull()][object]$Body)
    try {
        if ($null -eq $Body) { return '' }
        if ($Body -is [string]) { if (-not $Body.Trim().StartsWith('{')) { return '' }; $Body = $Body | ConvertFrom-Json -ErrorAction Stop }
        $v = Get-PimUplinkField $Body 'supersededBy'
        if ($v -isnot [string]) { return '' }
        $v = $v.Trim()
        if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$') { return '' }
        return $v
    } catch { return '' }
}

function Invoke-PimUplinkCycle {
    <#
      One cycle with every seam injected (tests run it offline):
        -GetSetting { param($Name) } / -SetSetting { param($Name, $Value) } -- pim.Settings
        -Send { param($Record, $Endpoint, $AccessCode) }                     -- returns @{ Status; Reason; Body? } (Send-PimUplinkRecord)
          §100.39: a heartbeat response carrying `supersededBy: <licenceId>` is stored in pim.Settings 'LicenceSupersededBy'
          (a plain string); the licence-request job (every 30 min) then knocks with currentLicenceId (PIM-LicenceRequest.ps1).
        -Runs <job run history>  -License <Get-PimLicense>  -ProHere <bool>
      Returns @{ ran; mode; sent; failed; heartbeat; message }.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting, [Parameter(Mandatory)][scriptblock]$Send,
          [bool]$Enabled = $false, [string]$InstallKey = '', [string]$Version = '', [AllowNull()][object]$Ring, [object[]]$Runs = @(),
          [AllowNull()][object]$License, [bool]$ProHere = $false, [string]$TenantId = '', [string]$RuntimeIdentity = 'mi-container',
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxPerCycle = $script:PimUplinkMaxRunsPerCycle, [int]$PauseMs = 0,
          # PIM 100.10 / framework 8.7 UPLINK-SETUP: the Kind=setup report (identified mode only; daily + on change).
          [bool]$SetupEnabled = $false, [AllowNull()][object]$SetupFacts = $null, [bool]$SetupExtended = $false,
          # PIM 100.36: @{ sqlUsedMb; sqlMaxMb } (Get-PimUplinkSqlSpace) -> the IDENTIFIED heartbeat's Counts; $null = left out.
          [AllowNull()][hashtable]$SqlSpace = $null,
          # framework 8.11 ASSET-COUNTS (owner 2026-10-10): @{ users; guests; servicePrincipals } the tick recorded
          # (pim.Settings 'TenantObjectCounts') -> the IDENTIFIED heartbeat's Counts; a missing / non-number key is left out.
          [AllowNull()][hashtable]$AssetCounts = $null,
          # PIM 100.34: send FixKind unless PIM_UPLINK_FIXKIND is 0/false/off/no (ON by default -- Invardia live 6f2dce4).
          [bool]$FixKind = (Test-PimUplinkFixKindEnabled))
    $NowUtc = $NowUtc.ToUniversalTime()
    $endpoint = "$(& $GetSetting 'UplinkEndpoint')".Trim()
    $sender = Resolve-AitUplinkSender -Enabled $Enabled -InstallKey $InstallKey -Endpoint $endpoint
    if ($sender.Mode -eq 'disabled') {
        # §11 opt-out: switched OFF after it was on -> ONE 'optout' report (with the credential telemetry used), then silence.
        $st0 = & $GetSetting 'UplinkState'
        if ((Get-PimUplinkConsentAction -State $st0 -Enabled $false) -ne 'optout') { return @{ ran = $false; mode = 'disabled'; sent = 0; failed = 0; heartbeat = $false; message = "telemetry is off (feature 'telemetry.uplink')" } }
        $cred = Resolve-AitUplinkSender -Enabled $true -InstallKey $InstallKey -Endpoint $endpoint
        $rec = New-PimUplinkConsentReport -Kind optout -Mode $cred.Mode -Version $Version -Ring $Ring -InstallId "$(& $GetSetting 'TelemetryInstallId')" -TenantId $TenantId -Now $NowUtc
        $ok = $true; $why = ''
        if ($rec) { $r = & $Send $rec $cred.Endpoint $cred.AccessCode; $ok = ("$($r.Status)" -eq 'ok'); $why = "$($r.Reason)" }
        $msg = if ($ok) { "telemetry is off -- the opt-out was reported to Invardia; nothing else is sent" } else { "telemetry is off -- the opt-out report was NOT delivered ($why); it is retried next cycle, nothing else is sent" }
        $ns = [ordered]@{}; if ($st0) { foreach ($pp in $st0.PSObject.Properties) { $ns[$pp.Name] = $pp.Value } }
        if ($ok) { $ns['consent'] = 'off'; $ns['consentUtc'] = $NowUtc.ToString('o') }
        $ns['lastCycleUtc'] = $NowUtc.ToString('o'); $ns['lastResult'] = $msg
        & $SetSetting 'UplinkState' ([pscustomobject]$ns)
        return @{ ran = $true; mode = 'disabled'; sent = $(if ($ok -and $rec) { 1 } else { 0 }); failed = $(if ($ok) { 0 } else { 1 }); heartbeat = $false; consent = $(if ($ok) { 'optout' } else { '' }); message = $msg }
    }
    $iid = "$(& $GetSetting 'TelemetryInstallId')".Trim()
    if ($iid -notmatch '^[0-9a-fA-F-]{36}$') { $iid = [guid]::NewGuid().ToString(); & $SetSetting 'TelemetryInstallId' $iid }
    $state = & $GetSetting 'UplinkState'
    $lastHb = if ($state -and $state.PSObject.Properties['lastHeartbeatUtc']) { $state.lastHeartbeatUtc } else { $null }
    # The FLOOR: the first cycle starts it at NOW-24h, so switching telemetry on reports the last day, not the whole history.
    # It never moves after that; each job then has its own watermark (jobMarks) that moves only when ITS report landed.
    $floor = if ($state -and $state.PSObject.Properties['runWatermarkUtc'] -and "$($state.runWatermarkUtc)") { $state.runWatermarkUtc } else { $NowUtc.AddHours(-24).ToString('o') }
    $marks = @{}
    if ($state -and $state.PSObject.Properties['jobMarks'] -and $state.jobMarks) {
        if ($state.jobMarks -is [System.Collections.IDictionary]) { foreach ($k in $state.jobMarks.Keys) { $marks["$k"] = "$($state.jobMarks[$k])" } }
        else { foreach ($p in $state.jobMarks.PSObject.Properties) { $marks["$($p.Name)"] = "$($p.Value)" } }
    }
    $common = @{ Mode = $sender.Mode; Product = $script:PimUplinkProduct; Version = $Version; Ring = $Ring; InstallId = $iid; TenantId = $TenantId; Now = $NowUtc }
    $sent = 0; $failed = 0; $why = @(); $supNote = ''; $hbSent = $false; $stopped = $false; $budget = [Math]::Max(1, $MaxPerCycle)
    $post = { param($rec) if ($sent -gt 0 -and $PauseMs -gt 0) { Start-Sleep -Milliseconds $PauseMs }; & $Send $rec $sender.Endpoint $sender.AccessCode }
    # §11 opt-in: switched back ON after an opt-out -> ONE 'optin' report FIRST. Until it lands nothing else is sent (Invardia
    # still has this environment as opted out), and nothing from the opted-out period is ever sent: the floor restarts NOW.
    $consent = 'on'
    if ((Get-PimUplinkConsentAction -State $state -Enabled $true) -eq 'optin') {
        $oi = New-PimUplinkConsentReport -Kind optin -Mode $sender.Mode -Version $Version -Ring $Ring -InstallId $iid -TenantId $TenantId -Now $NowUtc
        $r = & $post $oi
        if ("$($r.Status)" -eq 'ok') { $sent++; $floor = $NowUtc.ToString('o'); $marks = @{}; $lastHb = $null }
        else { $failed++; $stopped = $true; $consent = 'off'; $why += "optin: $($r.Reason)" }
    }
    if (-not $stopped -and (Get-PimUplinkHeartbeatDue -LastHeartbeatUtc $lastHb -NowUtc $NowUtc)) {
        # PIM 100.36: the SQL space, identified heartbeat only, both numbers or neither (never a 0 / a guess).
        $hbCounts = $null
        if ($sender.Mode -eq 'identified' -and $SqlSpace -and $SqlSpace.ContainsKey('sqlUsedMb') -and $SqlSpace.ContainsKey('sqlMaxMb') -and
            $null -ne $SqlSpace['sqlUsedMb'] -and $null -ne $SqlSpace['sqlMaxMb'] -and [int64]$SqlSpace['sqlMaxMb'] -gt 0) {
            $hbCounts = @{ sqlUsedMb = [int64]$SqlSpace['sqlUsedMb']; sqlMaxMb = [int64]$SqlSpace['sqlMaxMb'] }
        }
        if ($sender.Mode -eq 'identified' -and $AssetCounts) {
            foreach ($k in 'users', 'guests', 'servicePrincipals', 'groups') {
                $n = 0L
                if ($AssetCounts.ContainsKey($k) -and $null -ne $AssetCounts[$k] -and [long]::TryParse("$($AssetCounts[$k])", [ref]$n) -and $n -ge 0) {
                    if ($null -eq $hbCounts) { $hbCounts = @{} }
                    $hbCounts[$k] = $n
                }
            }
        }
        $hb = New-AitUplinkReport -Kind heartbeat @common -Edition (Get-PimUplinkEdition -License $License -ProHere $ProHere) -Hosting 'container' `
                -RuntimeIdentity $RuntimeIdentity -LicenceState (Get-PimUplinkLicenceState -License $License) -Counts $hbCounts
        # §100.39 / framework §12.6b: the IDENTIFIED heartbeat names the installed licence (Invardia 1.0.230: optional `LicenceId`,
        # a GUID; a bad value refuses the whole report) so Invardia can answer `supersededBy`. Anonymous never carries it.
        $lid = if ($License) { "$($License.LicenseId)".Trim().ToLowerInvariant() } else { '' }
        if ($hb -and $sender.Mode -eq 'identified' -and $lid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            $hb | Add-Member -NotePropertyName 'LicenceId' -NotePropertyValue $lid -Force
        }
        $r = & $post $hb
        if ("$($r.Status)" -eq 'ok') { $sent++; $hbSent = $true; $lastHb = $NowUtc.ToString('o') } else { $failed++; $stopped = $true; $why += "heartbeat: $($r.Reason)" }
        # §100.39: Invardia re-issued the installed licence -> keep its successor's id for the licence-request job. Only a
        # well-formed id is kept; a missing / malformed answer changes nothing; nothing here can fail the cycle.
        if ("$($r.Status)" -eq 'ok') {
            try {
                $sup = ''; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains('Body')) { $sup = Get-PimUplinkSupersededBy -Body $r['Body'] } }
                           elseif ($r.PSObject.Properties['Body']) { $sup = Get-PimUplinkSupersededBy -Body $r.Body }
                if ($sup) {
                    $prevSup = ''; try { $pv = & $GetSetting 'LicenceSupersededBy'; if ($pv -is [string]) { $prevSup = $pv.Trim() } } catch { }
                    if ($prevSup -ne $sup) { & $SetSetting 'LicenceSupersededBy' $sup }
                    $supNote = "; Invardia re-issued the licence (superseded by $sup) -- the licence request asks for it"
                }
            } catch { $supNote = "" }
        }
    }
    # PIM 100.10 (framework 8.7): the SETUP report -- identified only (anonymous Community sends nothing of this), its own
    # switch, once a day and on every change of state. Its state (UplinkSetupState) moves only when the report landed.
    $setupSent = $false
    if (-not $stopped -and $SetupEnabled -and $sender.Mode -eq 'identified' -and $null -ne $SetupFacts -and (Get-Command New-PimSetupReport -ErrorAction SilentlyContinue)) {
        $sst = $null; try { $sst = & $GetSetting 'UplinkSetupState' } catch { $sst = $null }
        if ($sst -is [string]) { try { $sst = $sst | ConvertFrom-Json } catch { $sst = $null } }
        $prevSince = $null; if ($sst -and $sst.PSObject.Properties['since']) { $prevSince = $sst.since }
        $edition = Get-PimUplinkEdition -License $License -ProHere $ProHere
        $rep = New-PimSetupReport -Facts $SetupFacts -Product $script:PimUplinkProduct -Version $Version -Ring $Ring -Edition $edition -Extended:$SetupExtended -PreviousSince $prevSince -NowUtc $NowUtc
        if (Get-PimSetupReportDue -State $sst -Fingerprint $rep.fingerprint -NowUtc $NowUtc) {
            $r = & $post $rep.record
            if ("$($r.Status)" -eq 'ok') {
                $sent++; $setupSent = $true
                & $SetSetting 'UplinkSetupState' ([pscustomobject][ordered]@{ lastSentUtc = $NowUtc.ToString('o'); fingerprint = $rep.fingerprint; extended = [bool]$SetupExtended; since = [pscustomobject]$rep.since })
            } else { $failed++; $stopped = $true; $why += "setup: $($r.Reason)" }
        }
    }
    $plan = Get-PimUplinkRunPlan -Runs $Runs -SinceUtc $floor -SinceByJob $marks
    $left = 0
    foreach ($p in @($plan.reports)) {
        # STOP at the first failure (a 429 says "wait") and at the per-cycle budget: the rest keep their watermark.
        if ($stopped -or $sent -ge $budget) { $left++; continue }
        $cls = if ($p.outcome -eq 'failed') { Get-PimUplinkErrorClass -Text $p.errorText } else { '' }
        $rec = New-AitUplinkReport -Kind run @common -Job $p.job -Outcome $p.outcome -DurationMs $p.durationMs -ErrorClass $cls -ErrorText $p.errorText `
                 -Counts @{ runs = $p.runCount }
        # 100.34: fixKind beside the class -- added HERE, not in the framework client (sync/_AitUplink.ps1 must stay
        # byte-identical), and only behind PIM_UPLINK_FIXKIND until Invardia's schema has the field.
        if ($rec -and $cls -and $FixKind) { $rec | Add-Member -NotePropertyName 'FixKind' -NotePropertyValue (Get-PimUplinkFixKind -ErrorClass $cls) -Force }
        $r = & $post $rec
        if ("$($r.Status)" -eq 'ok') { $sent++; $marks[$p.job] = $p.finishedUtc }
        else { $failed++; $stopped = $true; $left++; $why += "$($p.job): $($r.Reason)" }
    }
    # GUARD-1 (framework, 2026-10-04): every guard whose last trip is newer than its last send goes as a Kind 'guard' record
    # (PIM-Guard.ps1). Invardia opens / updates the support ticket from it. Same budget and stop-at-first-failure as the runs.
    $guardsSent = 0
    if (-not $stopped -and (Get-Command Select-PimGuardTelemetryDue -ErrorAction SilentlyContinue)) {
        $gs = $null; try { $gs = & $GetSetting 'GuardTrips' } catch { $gs = $null }
        if ($gs -is [string]) { try { $gs = $gs | ConvertFrom-Json } catch { $gs = $null } }
        foreach ($e in @(Select-PimGuardTelemetryDue -State $gs)) {
            if ($stopped -or $sent -ge $budget) { $left++; continue }
            $rec = New-PimGuardUplinkRecord -Entry $e -Mode $sender.Mode -Product $script:PimUplinkProduct -Version $Version -Ring $Ring -InstallId $iid -TenantId $TenantId
            if (-not $rec) { continue }
            $r = & $post $rec
            if ("$($r.Status)" -eq 'ok') { $sent++; $guardsSent++; $e | Add-Member -NotePropertyName lastSentUtc -NotePropertyValue $NowUtc.ToString('o') -Force }
            else { $failed++; $stopped = $true; $left++; $why += "guard $($e.guardId): $($r.Reason)" }
        }
        if ($guardsSent) { try { & $SetSetting 'GuardTrips' $gs } catch { $why += "guard send marks not saved: $($_.Exception.Message)" } }
    }
    $msg = "$($sender.Mode): $sent sent$(if ($guardsSent) { " ($guardsSent guard record(s))" })$(if ($setupSent) { ' (setup report)' })$(if ($failed) { ", $failed failed -- $(@($why | Select-Object -First 3) -join '; ')" })$(if ($left) { ", $left left for the next cycle" })$supNote"
    & $SetSetting 'UplinkState' ([pscustomobject][ordered]@{ mode = $sender.Mode; lastHeartbeatUtc = $lastHb; runWatermarkUtc = $floor; jobMarks = [pscustomobject]$marks
                                                             consent = $consent; lastCycleUtc = $NowUtc.ToString('o'); lastResult = $msg })
    return @{ ran = $true; mode = $sender.Mode; sent = $sent; failed = $failed; left = $left; heartbeat = $hbSent; setup = $setupSent; message = $msg }
}

function Invoke-PimUplinkJob {
    <#
      Job 'uplink' (hourly). Inert unless the feature 'telemetry.uplink' is ON. Key: $env:PIM_UPLINK_KEY (a Container Apps
      secret, never a file in the image, never returned by any API). Settings: UplinkState (shown on the Jobs page through
      the run detail), TelemetryInstallId, UplinkEndpoint (optional; default Invardia's).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $on = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.uplink' -Quiet))
    # §11: OFF still runs ONE check -- an install that was on and is now off reports its opt-out once (Invoke-PimUplinkCycle).
    # Never on = nothing is sent and nothing is called; no SQL store while off = nothing to check, quietly.
    $offDetail = "uplink: off (feature 'telemetry.uplink')"
    if (-not (Get-Command New-AitUplinkReport -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AitUplink.framework.ps1') }
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { if (-not $on) { return [pscustomobject]@{ ran = $false; whatIf = [bool]$WhatIf; detail = $offDetail } }; throw '[uplink] no SQL store -- the telemetry state cannot be read' }
    # PLAIN scriptblocks, never .GetNewClosure() (Test-PimHybridWorker L19): they read $cs / $WhatIf through dynamic scope.
    $get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $set = { param($n, $v) if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } }
    # §100.39: Send-PimUplinkRecord = the framework's Send-AitUplink, unchanged, plus the response body (supersededBy).
    $send = { param($rec, $ep, $code) if ($WhatIf) { @{ Status = 'ok'; Reason = 'what-if' } } else { Send-PimUplinkRecord -Record $rec -Endpoint $ep -AccessCode $code } }
    $sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $verFile = Join-Path $sol 'VERSION'
    $ver = if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } elseif ($env:PIM_VERSION) { "$env:PIM_VERSION" } else { '' }
    $tid = ''; if (Get-Command Resolve-PimLicenseTenantId -ErrorAction SilentlyContinue) { try { $tid = "$(Resolve-PimLicenseTenantId)" } catch { } }
    $lic = $null; try { $lic = Get-PimLicense } catch { $lic = $null }
    $proHere = $false; if ($lic -and (Get-Command Test-PimLicenseIsProForTenant -ErrorAction SilentlyContinue)) { try { $proHere = [bool](Test-PimLicenseIsProForTenant -License $lic -TenantId $tid).pro } catch { } }
    if (-not (Get-Command Resolve-PimUplinkRing -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-UplinkSetup.ps1') }
    # 100.10 (Invardia 2026-10-09: "update level unknown" for every PIM install -- Reports.Ring empty): PIM_UPDATE_RING is set on
    # the UPDATE job only, and this job runs in the tick job. The environment's own record (UpdateState) carries the ring too.
    $us = $null; try { $us = & $get 'UpdateState'; if ($us -is [string]) { $us = $us | ConvertFrom-Json } } catch { $us = $null }
    $ring = Resolve-PimUplinkRing -EnvRing "$env:PIM_UPDATE_RING" -UpdateState $us
    $rid = if ($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT) { 'mi-container' } else { 'spn-certificate' }
    $runs = @(); if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { try { $runs = @(Get-PimJobRunHistory) } catch { $runs = @() } }
    $key = if (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue) { Resolve-PimInvardiaInstallKey -GetSetting $get } else { "$env:PIM_UPLINK_KEY" }
    # 100.10: the setup report -- its own switch (feature 'telemetry.setup', ON by default; it only ever sends with an install key).
    $setupOn = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'telemetry.setup' -Quiet))
    $facts = $null
    if ($on -and $setupOn -and "$key".Trim()) {
        $msp = ''; $down = $null
        try { if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) { $sc = Get-PimActiveScenario; if ("$($sc.role)" -eq 'msp-managed') { $msp = 'Slave' } elseif ("$($sc.role)" -eq 'msp-master') { $msp = 'Master' } } } catch { }
        try { if ($msp -eq 'Slave' -and (Get-Command Test-PimFeatureEnabled -ErrorAction SilentlyContinue)) { $down = [bool](Test-PimFeatureEnabled -Key 'msp.downlink') } } catch { $down = $null }
        try { $facts = Get-PimSetupFacts -GetSetting $get -Runs $runs -License $lic -ProHere $proHere -InstallKey $key -MspRole $msp -DownlinkOn $down -NowUtc $NowUtc } catch { $facts = $null }
    }
    # 100.36: the SQL space for the IDENTIFIED heartbeat (the store's own MI connection); a failed read = both numbers left out.
    $sqlSpace = $null
    if ($on -and "$key".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) {
        $spaceSql = $script:PimUplinkSqlSpaceQuery
        $sqlSpace = Get-PimUplinkSqlSpace -Query { Invoke-PimSqlQuery -ConnectionString $cs -Sql $spaceSql }
    }
    # framework 8.11 ASSET-COUNTS: what the tick's tenant-cache refresh recorded (members / guests / service principals).
    $assets = $null
    try {
        $tc = & $get 'TenantObjectCounts'; if ($tc -is [string] -and "$tc".Trim()) { $tc = $tc | ConvertFrom-Json }
        if ($tc) { $assets = @{ users = $tc.Members; guests = $tc.Guests; servicePrincipals = $tc.ServicePrincipals; groups = $tc.Groups } }
    } catch { $assets = $null }
    $r = Invoke-PimUplinkCycle -GetSetting $get -SetSetting $set -Send $send -Enabled $on -InstallKey $key -Version $ver -Ring $ring `
            -Runs $runs -License $lic -ProHere $proHere -TenantId $tid -RuntimeIdentity $rid -NowUtc $NowUtc -PauseMs $(if ($WhatIf) { 0 } else { 2500 }) `
            -SetupEnabled $setupOn -SetupFacts $facts -SetupExtended (Test-PimUplinkSetupExtended) -SqlSpace $sqlSpace -AssetCounts $assets
    [pscustomobject]@{ ran = [bool]$r.ran; whatIf = [bool]$WhatIf; detail = "uplink: $($r.message)" }
}
