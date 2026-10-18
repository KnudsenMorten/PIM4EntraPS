#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.158 -- CR3 RELEASE CONTROL, PIM's half (framework DOCS/REQUIREMENTS.md 12.11e; the wire shapes MATCH
  SecurityInsight's, agreed with SI 2026-10-15). Everything here is PURE: the publish tool, the updater and the uplink job
  call it with what they already read.

.DESCRIPTION
  1. changedScopes -- which parts of PIM a release touched, from the release's changed files (Get-PimChangedScopes).
     Sent on the publish call (&changedScopes=id,id) and on the ring call ("changedScopes": [..]); '*' = all (a core file,
     an unknown file, or more than 30 scopes). Scope ids (lower-case):
        engine                core engine (engine/_shared, tools/pim-engine)      -> a core file = '*' (all scopes)
        engine.<area>         an engine area folder (engine/hybrid-ad -> engine.hybrid-ad, engine/msp -> engine.msp, ...),
                              workloads -> engine.workloads, connectors -> engine.connectors, templates -> engine.templates,
                              tools/pim-hybrid-worker -> engine.hybrid-ad, tools/pim-rfa -> engine.rfa
        manager               tools/pim-manager
        updater               tools/pim-engine/update-job-entry.ps1, tools/setup/Deploy-PimUpdateJob.ps1, the Invardia update
                              client (PIM-InvardiaUpdate.ps1, InvardiaUpdate.verify.ps1), PIM-JobSelfId.ps1
        scheduler             tools/pim-scheduler, PIM-Scheduler.ps1, PIM-JobLanes.ps1, PIM-JobCadence.ps1
        sql-schema            sql/
        setup                 tools/setup (but the per-release version stamp install-parameters.json), setup/, config*/,
                              solution.*.json
        activator             tools/pim-activator
     Never a scope: docs, tests, README / RELEASENOTES / VERSION / LICENSE / CLAUDE.md, internal/, output/, the developer
     tools at tools/ root (Capture-*, Run-PimGuiValidation).
  2. The switches (one rule for both): PIM_PUBLISH_CHANGEDSCOPES (the publish tool) and PIM_Telemetry_ReleaseControl (the
     heartbeat fields): on / off, and AUTO (empty, the default) = ring 0 only, until Invardia confirms it (100.158).
  3. wave -- read from the SIGNED manifest only (the updater records what it was served: pim.Settings 'ReleaseWave').
  4. The heartbeat fields (identified only, left out while nothing is recorded): wave = null | { name; version; ring },
     releaseMode = null | { version; sinceUtc; untilUtc; everyMinutes } -- the release window after an engine-changing release
     (the engine's Strict mode start, framework 12.11b), 4 hours for PIM (12.11e item 3). everyMinutes is what PIM REALLY
     does: 15 -- inside the window the scheduler runs the uplink job every 15 minutes and the heartbeat goes every 15 minutes
     (Get-PimReleaseModeJobMinutes; outside the window both stay hourly, exactly as before).
  5. Testing / Stable per engine scope (12.11e item 3, PIM 100.158 (c)): pim.Settings 'ScopeStability' keeps one hash per
     scope of THIS install's own code (Get-PimScopeCodeHashes, re-hashed only when VERSION changes). A scope whose hash a
     release changed is Testing (a core change = every scope); it is Stable after 3 good UTC days of its runs with no code
     change (Update-PimScopeStability: a day with a failed run starts the count again). Sent on the identified heartbeat as
     `scopeStability` only when PIM_Telemetry_ScopeStability is on (OFF by default until Invardia confirms the field).
  ASCII only; PS 5.1 + 7; no module.
#>
Set-StrictMode -Off

function Get-PimReleaseControlScopeIds {
    <# PURE. The fixed scope ids (engine.<area> is open: any lower-case area name). #>
    return @('engine', 'manager', 'updater', 'scheduler', 'sql-schema', 'setup', 'activator')
}

function Get-PimReleaseModeHours { <# PURE. framework 12.11e item 3: PIM's release window, hours. #> return 4 }
function Get-PimReleaseModeEveryMinutes { <# PURE. framework 12.11e item 3: PIM reports every 15 min inside the release window. #> return 15 }

function Get-PimReleaseModeWindow {
    <#
      PURE. The release window NOW, from -StrictState (Get-PimGuardStrictState: sinceUtc; version; readError): the 4 hours after
      the engine-changing release's first run. [pscustomobject]@{ version; sinceUtc; untilUtc } inside it; $null outside it,
      when nothing started it, or when the state could not be read (never a guess).
    #>
    param([AllowNull()][object]$StrictState, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $StrictState -or "$($StrictState.readError)".Trim()) { return $null }
    $d = [datetime]::MinValue
    $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not "$($StrictState.sinceUtc)".Trim() -or -not [datetime]::TryParse("$($StrictState.sinceUtc)", [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $null }
    $since = $d.ToUniversalTime(); $until = $since.AddHours((Get-PimReleaseModeHours)); $now = $NowUtc.ToUniversalTime()
    if ($now -lt $since -or $now -ge $until -or -not "$($StrictState.version)".Trim()) { return $null }
    return [pscustomobject][ordered]@{ version = "$($StrictState.version)".Trim(); sinceUtc = $since.ToString('o'); untilUtc = $until.ToString('o') }
}

function Get-PimReleaseModeJobMinutes {
    <#
      PURE. The uplink job's cadence override (PIM 100.158 (a)): inside the release window the job runs every 15 minutes --
      or at its own interval when an operator already set it shorter (an override only ever SHORTENS); outside the window,
      or when the window cannot be read, 0 = no override (the job keeps its own interval, hourly by default).
    #>
    param([AllowNull()][object]$StrictState, [datetime]$NowUtc = [datetime]::UtcNow, [int]$IntervalMinutes = 60)
    if ($null -eq (Get-PimReleaseModeWindow -StrictState $StrictState -NowUtc $NowUtc)) { return 0 }
    $m = Get-PimReleaseModeEveryMinutes
    if ($IntervalMinutes -gt 0 -and $IntervalMinutes -le $m) { return 0 }   # already as fast or faster: nothing to shorten
    return $m
}
function Get-PimChangedScopesMax { <# PURE. More scopes than this = '*'. #> return 30 }

function Test-PimReleaseControlOn {
    <#
      PURE. One rule for PIM_PUBLISH_CHANGEDSCOPES and PIM_Telemetry_ReleaseControl: 1/on/true/yes = on; 0/off/false/no = off;
      empty / auto / anything else = AUTO = on for ring 0 only (100.158: "auto = ring 0 only until confirmed").
    #>
    param([AllowNull()][string]$Value, [AllowNull()][object]$Ring)
    $v = "$Value".Trim().ToLowerInvariant()
    if ($v -in @('1', 'on', 'true', 'yes')) { return $true }
    if ($v -in @('0', 'off', 'false', 'no')) { return $false }
    $r = -1
    if ($null -ne $Ring -and [int]::TryParse("$Ring".Trim(), [ref]$r)) { return ($r -eq 0) }
    return $false
}

function Test-PimChangedScopesOn {
    <#
      PURE. PIM_PUBLISH_CHANGEDSCOPES since Invardia CONFIRMED the field (2026-10-16, Invardia 1.0.480: ids ^[A-Za-z0-9._-]{1,80}$,
      at most 90, "*" alone = all; no refusal seen from PIM): ON for every ring call by default; 0/off/false/no = off.
      (The heartbeat's wave / releaseMode keep Test-PimReleaseControlOn's AUTO = ring 0 only until confirmed separately.)
    #>
    param([AllowNull()][string]$Value)
    return -not ("$Value".Trim().ToLowerInvariant() -in @('0', 'off', 'false', 'no'))
}

function Test-PimReleaseControlFieldsOn {
    <#
      PURE. PIM_Telemetry_ReleaseControl since Invardia CONFIRMED the heartbeat fields `wave` / `releaseMode` on every ring
      (2026-10-16; its validator reads the lower-case keys first; none refused from ring 0 since 2.4.639): ON by default on
      every ring; 0/off/false/no = off. A malformed field is refused 422 naming it -> the cycle's resend-without + 24 h hold.
    #>
    param([AllowNull()][string]$Value)
    return -not ("$Value".Trim().ToLowerInvariant() -in @('0', 'off', 'false', 'no'))
}

function Get-PimRingBaseVersion {
    <#
      PURE. Invardia 2026-10-16: on a RING call changedScopes is the UNION of every change between the version that ring holds
      NOW and the target (2.4.638 -> 2.4.640 = 2.4.639's + 2.4.640's scopes). -State = GET /api/releases/pim-manager/state
      ({ rings: { "<n>": { version } } }). Returns that ring's current version when it is a release version BELOW -Target,
      else '' (no state, the ring empty, the same or a newer version) -- the caller then falls back to the previous tag.
    #>
    param([AllowNull()][object]$State, [Parameter(Mandatory)][int]$Ring, [Parameter(Mandatory)][string]$Target)
    if ($null -eq $State) { return '' }
    $rings = if ($State -is [System.Collections.IDictionary]) { $State['rings'] } else { $State.rings }
    if ($null -eq $rings) { return '' }
    $rk = "$Ring"
    $r = if ($rings -is [System.Collections.IDictionary]) { $rings[$rk] } elseif ($rings.PSObject.Properties[$rk]) { $rings.$rk } else { $null }
    if ($null -eq $r) { return '' }
    $v = if ($r -is [System.Collections.IDictionary]) { "$($r['version'])" } else { "$($r.version)" }
    $v = $v.Trim()
    $cv = $null; $tv = $null
    if (-not [version]::TryParse($v, [ref]$cv) -or -not [version]::TryParse("$Target".Trim(), [ref]$tv)) { return '' }
    if ($cv -ge $tv) { return '' }
    return $v
}

function Get-PimChangedScopeOfFile {
    <#
      PURE. The scope of ONE changed file: a scope id, '*' (all -- a core or unknown file), or '' (not a scope: docs, tests ...).
      -Path: repo-relative or solution-relative, either slash.
    #>
    param([AllowNull()][string]$Path)
    $p = ("$Path".Trim() -replace '\\', '/').TrimStart('/')
    if (-not $p) { return '' }
    if ($p -match '^(?i)SOLUTIONS/PIM4EntraPS/') { $p = $p.Substring('SOLUTIONS/PIM4EntraPS/'.Length) }
    elseif ($p -match '^(?i)(SOLUTIONS|DOCS|TOOLS|FUNCTIONS|TESTS|sync|\.github)/') { return '' }   # not PIM's tree
    $l = $p.ToLowerInvariant()
    # never a scope
    if ($l -match '^(docs|tests|internal|output)/') { return '' }
    if ($l -in @('readme.md', 'releasenotes.md', 'version', 'license', 'claude.md')) { return '' }
    if ($l -match '^[^/]+\.md$') { return '' }
    if ($l -match '^tools/(capture-[^/]+|run-pimguivalidation)\.ps1$') { return '' }
    if ($l -eq 'tools/setup/install-parameters.json') { return '' }   # the per-release version stamp
    # the updater (before the general tools/setup and engine rules)
    if ($l -in @('tools/pim-engine/update-job-entry.ps1', 'tools/setup/deploy-pimupdatejob.ps1', 'engine/_shared/pim-invardiaupdate.ps1',
                 'engine/_shared/invardiaupdate.verify.ps1', 'engine/_shared/pim-jobselfid.ps1')) { return 'updater' }
    # the scheduler
    if ($l -match '^tools/pim-scheduler/') { return 'scheduler' }
    if ($l -in @('engine/_shared/pim-scheduler.ps1', 'engine/_shared/pim-joblanes.ps1', 'engine/_shared/pim-jobcadence.ps1')) { return 'scheduler' }
    if ($l -match '^tools/pim-manager/') { return 'manager' }
    if ($l -match '^tools/pim-activator/') { return 'activator' }
    if ($l -match '^tools/pim-hybrid-worker/') { return 'engine.hybrid-ad' }
    if ($l -match '^tools/pim-rfa/') { return 'engine.rfa' }
    if ($l -match '^sql/') { return 'sql-schema' }
    if ($l -match '^(tools/setup|setup|config[^/]*)/') { return 'setup' }
    if ($l -match '^solution\.[^/]+\.json$') { return 'setup' }
    if ($l -match '^workloads/') { return 'engine.workloads' }
    if ($l -match '^connectors/') { return 'engine.connectors' }
    if ($l -match '^templates/') { return 'engine.templates' }
    if ($l -match '^engine/([^/]+)/') {
        $area = $Matches[1]
        if ($area -eq '_shared') { return '*' }   # a core file = all scopes (12.11e item 3)
        $id = ($area -replace '[^a-z0-9-]+', '-').Trim('-')
        if ($id) { return "engine.$id" }
        return '*'
    }
    if ($l -match '^tools/pim-engine/') { return '*' }   # core engine entry points
    return '*'   # unknown = the safe side: all
}

function Get-PimChangedScopes {
    <#
      PURE. The release's changedScopes from its changed files: sorted unique scope ids; @('*') when any file is core /
      unknown or more than 30 scopes; @() when nothing but docs / tests changed.
    #>
    param([AllowNull()][string[]]$Files = @())
    $set = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Files)) {
        $s = Get-PimChangedScopeOfFile -Path "$f"
        if (-not $s) { continue }
        if ($s -eq '*') { return @('*') }
        if (-not $set.Contains($s)) { $set.Add($s) }
    }
    if ($set.Count -gt (Get-PimChangedScopesMax)) { return @('*') }
    return @($set.ToArray() | Sort-Object)
}

function ConvertTo-PimChangedScopesQuery {
    <# PURE. The publish call's query value: 'a,b' or '*' (URL-escaped); '' when there is nothing to say. #>
    param([AllowNull()][string[]]$Scopes = @())
    $s = @(@($Scopes) | Where-Object { "$_".Trim() })
    if (-not $s.Count) { return '' }
    return [uri]::EscapeDataString(($s -join ','))
}

function Test-PimChangedScopesRefusal {
    <# PURE. Did Invardia refuse the call FOR the changedScopes field (a 400 / 422 naming it)? A 409 is never this. #>
    param([int]$Status, [AllowNull()][string]$Content)
    if ($Status -notin @(400, 422)) { return $false }
    return [bool]("$Content" -match '(?i)changedScopes')
}

function Test-PimChangedScopesHeld {
    <# PURE. Held for 24 h after Invardia refused the field (-RefusedUtc ISO text or $null). #>
    param([AllowNull()][object]$RefusedUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not "$RefusedUtc".Trim()) { return $false }
    $d = [datetime]::MinValue
    $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse("$RefusedUtc", [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $false }
    return ($NowUtc.ToUniversalTime() -lt $d.ToUniversalTime().AddHours(24))
}

function Get-PimNotApprovedText {
    <#
      PURE. Invardia's 409 { error: "notApproved"; reason } in plain words for the publish tool, or '' when the answer is not
      that refusal. framework 12.11e item 7: the product's publish tooling shows it plainly.
    #>
    param([int]$Status, [AllowNull()][string]$Content, [string]$Version = '', [int]$Ring = -1)
    if ($Status -ne 409) { return '' }
    $j = $null; try { $j = "$Content" | ConvertFrom-Json } catch { $j = $null }
    $err = if ($j -and $j.PSObject.Properties['error']) { "$($j.error)" } else { '' }
    if ($err -ne 'notApproved' -and "$Content" -notmatch 'notApproved') { return '' }
    $why = if ($j -and $j.PSObject.Properties['reason'] -and "$($j.reason)".Trim()) { " (Invardia: $("$($j.reason)".Trim()))" } else { '' }
    return ("NOT APPROVED: ring {0} for {1} needs the owner's approval in Invardia's back office{2}. This refused call opens his approval mail (once per version). Do not retry -- release again when release.approved for {1} arrives." -f $Ring, $Version, $why)
}

function ConvertTo-PimReleaseWaveRecord {
    <#
      PURE. What the updater records after a VERIFIED manifest (pim.Settings 'ReleaseWave'): the wave it was served -- read from
      the SIGNED manifest only -- or none. @{ wave = $null | @{ name; version; ring }; recordedUtc }.
    #>
    param([AllowNull()][string]$Wave, [AllowNull()][string]$Version, [AllowNull()][object]$Ring, [datetime]$NowUtc = [datetime]::UtcNow)
    $name = ("$Wave" -replace '[\x00-\x1F]', ' ').Trim()
    if ($name.Length -gt 100) { $name = $name.Substring(0, 100).Trim() }
    $r = -1; [void][int]::TryParse("$Ring".Trim(), [ref]$r)
    $w = $null
    if ($name -and "$Version".Trim() -match '^\d+\.\d+\.\d+$' -and $r -ge 0 -and $r -le 3) {
        $w = [ordered]@{ name = $name; version = "$Version".Trim(); ring = $r }
    }
    return [ordered]@{ wave = $w; recordedUtc = $NowUtc.ToUniversalTime().ToString('o') }
}

function Get-PimReleaseControlHeartbeatFields {
    <#
      PURE. The heartbeat's release-control fields, ONLY those that are known (a key left out = nothing recorded / cannot be
      read; a key with $null = recorded and none):
        wave         from -WaveRecord (pim.Settings 'ReleaseWave', object or JSON text): $null or { name; version; ring }
        releaseMode  from -StrictState (Get-PimGuardStrictState: sinceUtc; version; readError): inside the 4-hour window after
                     the engine-changing release's first run -> { version; sinceUtc; untilUtc; everyMinutes }, else $null.
    #>
    param([AllowNull()][object]$WaveRecord, [AllowNull()][object]$StrictState, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{}
    # a field of an object OR a dictionary (the record is a dictionary when built in-process, an object when read back)
    $g = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }; $pp = $o.PSObject.Properties[$n]; if ($pp) { return $pp.Value }; return $null }
    $wr = $WaveRecord
    if ($wr -is [string]) { if ("$wr".Trim()) { try { $wr = $wr | ConvertFrom-Json } catch { $wr = $null } } else { $wr = $null } }
    if ($null -ne $wr -and "$(& $g $wr 'recordedUtc')".Trim()) {
        $w = $null
        $wv = & $g $wr 'wave'
        if ($null -ne $wv) {
            $r = -1; [void][int]::TryParse("$(& $g $wv 'ring')", [ref]$r)
            $wn = "$(& $g $wv 'name')".Trim(); $wver = "$(& $g $wv 'version')".Trim()
            if ($wn -and $wver -match '^\d+\.\d+\.\d+$' -and $r -ge 0 -and $r -le 3) {
                $w = [pscustomobject][ordered]@{ name = $wn; version = $wver; ring = $r }
            }
        }
        $out['wave'] = $w
    }
    if ($null -ne $StrictState -and -not "$($StrictState.readError)".Trim()) {
        $rm = $null
        $win = Get-PimReleaseModeWindow -StrictState $StrictState -NowUtc $NowUtc
        if ($null -ne $win) {
            $rm = [pscustomobject][ordered]@{ version = $win.version; sinceUtc = $win.sinceUtc; untilUtc = $win.untilUtc; everyMinutes = (Get-PimReleaseModeEveryMinutes) }
        }
        $out['releaseMode'] = $rm
    }
    return $out
}

function Get-PimReleaseWaveHeader {
    <#
      PURE. PIM 100.158 (b) / framework 12.11e item 2: the Manager header while the install RUNS a wave version -- the recorded
      wave (pim.Settings 'ReleaseWave', object or JSON text) names a version equal to -RunningVersion (a leading 'v' ignored).
      @{ label = 'Ring <N> - Pre-release (<name>)'; wave = { name; version; ring } } -- or label '' and wave $null when no wave
      is recorded, the record is none / unreadable, or the install runs another version (then the header is as before).
    #>
    param([AllowNull()][object]$WaveRecord, [AllowNull()][string]$RunningVersion)
    $none = @{ label = ''; wave = $null }
    try {
        $f = Get-PimReleaseControlHeartbeatFields -WaveRecord $WaveRecord -StrictState $null
        if (-not $f.Contains('wave') -or $null -eq $f['wave']) { return $none }
        $w = $f['wave']
        $run = ("$RunningVersion".Trim() -replace '^(?i)v', '')
        if (-not $run -or $run -ne "$($w.version)") { return $none }
        return @{ label = ("Ring {0} - Pre-release ({1})" -f $w.ring, $w.name); wave = $w }
    } catch { return $none }
}

# ---------------------------------------------------------------------------------------------------------------------
# PIM 100.158 (c) / framework 12.11e item 3 -- TESTING / STABLE PER ENGINE SCOPE.
# pim.Settings 'ScopeStability' = { version; watermarkUtc; scopes: { "<id>": { hash; state; sinceUtc; version; goodDays; day;
#   ownOk; ownFailed; allOk; allFailed } } }. The uplink job keeps it (every cycle, best-effort, never failing a run) and
# sends `scopeStability` = [ { id; state; sinceUtc; version; goodDays } ] on the identified heartbeat only when
# PIM_Telemetry_ScopeStability is on (Test-PimScopeStabilityOn: OFF by default).
#   * a scope's hash = SHA-256 over "<relative path> <file SHA-256>" of the install's files of that scope (the changedScopes
#     map, Get-PimChangedScopeOfFile); the core files (map '*') are the scope 'engine', and a change there = every scope.
#   * the FIRST record (no state yet) is a baseline: every scope Stable (nothing is known about an earlier release).
#   * a day = a UTC day. It is judged when it has passed: a failed run of the scope that day -> goodDays 0; else at least one
#     ok / warning run -> goodDays + 1; no run -> unchanged. 3 good days -> Stable. A scope with jobs of its own
#     (engine.hybrid-ad, engine.rfa, engine.msp) is judged on those jobs on a day they ran, else -- like every other scope --
#     on all of the install's runs.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimScopeStabilityGoodDays { <# PURE. framework 12.11e item 3: Stable after 3 good daily runs. #> return 3 }

function Test-PimScopeStabilityOn {
    <# PURE. PIM_Telemetry_ScopeStability: OFF by default (Invardia has not confirmed the field); only 1/on/true/yes = on. #>
    param([AllowNull()][string]$Value)
    return ("$Value".Trim().ToLowerInvariant() -in @('1', 'on', 'true', 'yes'))
}

function Get-PimScopeOfJobId {
    <# PURE. The scope a job belongs to by its Invardia job id ('pim-<type>'), or '' = no scope of its own (the whole install). #>
    param([AllowNull()][string]$JobId)
    $j = ("$JobId".Trim().ToLowerInvariant() -replace '^pim-', '')
    if ($j -match '^hybrid-ad') { return 'engine.hybrid-ad' }
    if ($j -match '^rfa') { return 'engine.rfa' }
    if ($j -match '^msp') { return 'engine.msp' }
    return ''
}

function Get-PimScopeCodeHashes {
    <#
      The hash of each scope of THIS install's code (see the block above): an ordered dictionary id -> SHA-256 (hex), sorted
      by id; 'engine' carries the core files. $null when the tree cannot be read (then nothing is decided). Never throws.
      Skips docs / tests / internal / output (never a scope) and any .git / node_modules folder.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $script:PimScopeHashError = ''
    try {
        # the root's FullName from the SAME provider call as its children (a short 8.3 temp path would otherwise differ)
        $rootFull = (Get-Item -LiteralPath $SolutionRoot -Force -ErrorAction Stop).FullName.TrimEnd('\', '/')
        $buckets = @{}
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            foreach ($f in @(Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force -ErrorAction Stop)) {
                if (-not $f.FullName.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) { continue }
                $rel = ($f.FullName.Substring($rootFull.Length).TrimStart('\', '/') -replace '\\', '/')
                if ($rel -match '(^|/)(\.git|node_modules)(/|$)') { continue }
                # solution-relative here -- named repo-relative for the map, whose bare tools/ / tests/ mean the REPO-root trees
                $s = Get-PimChangedScopeOfFile -Path "SOLUTIONS/PIM4EntraPS/$rel"
                if (-not $s) { continue }
                if ($s -eq '*') { $s = 'engine' }
                if (-not $buckets.ContainsKey($s)) { $buckets[$s] = New-Object System.Collections.Generic.List[string] }
                $h = -join ($sha.ComputeHash([IO.File]::ReadAllBytes($f.FullName)) | ForEach-Object { $_.ToString('x2') })
                $buckets[$s].Add("$rel $h")
            }
            if (-not $buckets.Count) { return $null }
            $out = [ordered]@{}
            foreach ($k in @($buckets.Keys | Sort-Object)) {
                $all = (@($buckets[$k].ToArray()) | Sort-Object -CaseSensitive) -join "`n"
                $out[$k] = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($all)) | ForEach-Object { $_.ToString('x2') })
            }
            return $out
        } finally { $sha.Dispose() }
    } catch { $script:PimScopeHashError = "$($_.Exception.Message)"; return $null }
}

function ConvertTo-PimRcUtcText {
    <# PURE. A time as ISO UTC text. PowerShell 7's ConvertFrom-Json turns a stored ISO stamp into a [datetime] of Kind Local --
       "$value" would drop the zone (the Get-PimUtcStamp lesson), so a [datetime] is converted, never stringified. #>
    param([AllowNull()][object]$Value)
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq [DateTimeKind]::Local) { $Value.ToUniversalTime() } else { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $d.ToString('o')
    }
    return "$Value".Trim()
}

function ConvertTo-PimScopeStabilityState {
    <# PURE. The stored record (object, dictionary or JSON text) as @{ version; watermarkUtc; scopes = ordered id -> hashtable }; junk = empty. #>
    param([AllowNull()][object]$State)
    $o = @{ version = ''; watermarkUtc = ''; scopes = [ordered]@{} }
    $s = $State
    if ($s -is [string]) { if ("$s".Trim()) { try { $s = $s | ConvertFrom-Json } catch { $s = $null } } else { $s = $null } }
    if ($null -eq $s) { return $o }
    $g = { param($x, $n) if ($null -eq $x) { return $null }; if ($x -is [System.Collections.IDictionary]) { if ($x.Contains($n)) { return $x[$n] }; return $null }; $pp = $x.PSObject.Properties[$n]; if ($pp) { return $pp.Value }; return $null }
    $o.version = "$(& $g $s 'version')".Trim(); $o.watermarkUtc = ConvertTo-PimRcUtcText (& $g $s 'watermarkUtc')
    $sc = & $g $s 'scopes'
    if ($null -eq $sc) { return $o }
    $names = if ($sc -is [System.Collections.IDictionary]) { @($sc.Keys) } else { @($sc.PSObject.Properties | ForEach-Object { $_.Name }) }
    $n = { param($x) $i = 0; [void][int]::TryParse("$x", [ref]$i); if ($i -lt 0) { $i = 0 }; $i }
    foreach ($id in @($names | Sort-Object)) {
        $v = & $g $sc "$id"
        if ($null -eq $v -or "$id" -notmatch '^[a-z0-9][a-z0-9._-]{0,79}$') { continue }
        $st = "$(& $g $v 'state')".Trim().ToLowerInvariant(); if ($st -notin @('testing', 'stable')) { continue }
        $o.scopes["$id"] = @{ hash = "$(& $g $v 'hash')"; state = $st; sinceUtc = (ConvertTo-PimRcUtcText (& $g $v 'sinceUtc')); version = "$(& $g $v 'version')"
                              goodDays = (& $n (& $g $v 'goodDays')); day = "$(& $g $v 'day')"
                              ownOk = (& $n (& $g $v 'ownOk')); ownFailed = (& $n (& $g $v 'ownFailed')); allOk = (& $n (& $g $v 'allOk')); allFailed = (& $n (& $g $v 'allFailed')) }
    }
    return $o
}

function Test-PimScopeStabilityRehash {
    <# PURE. Hash the code again? Only when nothing is recorded or the running VERSION is not the recorded one. #>
    param([AllowNull()][object]$State, [AllowNull()][string]$Version)
    $s = ConvertTo-PimScopeStabilityState -State $State
    return (-not $s.scopes.Count -or "$($s.version)" -ne "$Version".Trim())
}

function Update-PimScopeStability {
    <#
      PURE. The next 'ScopeStability' record (see the block above) from the stored one, this install's scope hashes (-Hashes,
      $null = not re-hashed this cycle), the running -Version, and the run facts since the record's watermark (-RunFacts:
      [ @{ job = 'pim-<type>'; outcome = ok | warning | failed; finishedUtc } ]; $null = the run history could not be read).
      Returns @{ version; watermarkUtc; scopes } (ordered by id).
    #>
    param([AllowNull()][object]$State, [AllowNull()][System.Collections.IDictionary]$Hashes, [AllowNull()][string]$Version,
          [AllowNull()][object[]]$RunFacts, [datetime]$NowUtc = [datetime]::UtcNow, [int]$GoodDays = (Get-PimScopeStabilityGoodDays))
    $now = $NowUtc.ToUniversalTime(); $nowText = $now.ToString('o'); $today = $now.ToString('yyyy-MM-dd')
    $ver = "$Version".Trim()
    $cur = ConvertTo-PimScopeStabilityState -State $State
    $ownScopes = @('engine.hybrid-ad', 'engine.rfa', 'engine.msp')
    $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    $parse = { param($t) $t = ConvertTo-PimRcUtcText $t; $d = [datetime]::MinValue; if ("$t".Trim() -and [datetime]::TryParse("$t", [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $d.ToUniversalTime() }; return $null }
    $fresh = { param($h) @{ hash = "$h"; state = 'testing'; sinceUtc = $nowText; version = $ver; goodDays = 0; day = $today; ownOk = 0; ownFailed = 0; allOk = 0; allFailed = 0 } }
    # (1) the code: a re-hash decides which scopes a release changed
    if ($null -ne $Hashes -and $Hashes.Count) {
        $first = (-not $cur.scopes.Count)
        $engChanged = (-not $first -and (-not $cur.scopes.Contains('engine') -or "$($cur.scopes['engine'].hash)" -ne "$($Hashes['engine'])"))
        $next = [ordered]@{}
        foreach ($id in @($Hashes.Keys | ForEach-Object { "$_" } | Sort-Object)) {
            $h = "$($Hashes[$id])"
            if ($first) {
                $next[$id] = @{ hash = $h; state = 'stable'; sinceUtc = $nowText; version = $ver; goodDays = $GoodDays; day = ''; ownOk = 0; ownFailed = 0; allOk = 0; allFailed = 0 }
            } elseif ($engChanged -or -not $cur.scopes.Contains($id) -or "$($cur.scopes[$id].hash)" -ne $h) {
                $next[$id] = & $fresh $h
            } else { $next[$id] = $cur.scopes[$id] }
        }
        $cur.scopes = $next
        $cur.version = $ver
        if ($first) { $cur.watermarkUtc = $nowText }   # a baseline never judges the history before it
    }
    # (2) the runs: per Testing scope, count the day's runs; a day is judged when a later day starts
    $judge = {
        param($s, $id)
        $useOwn = (($ownScopes -contains $id) -and ($s.ownOk + $s.ownFailed) -gt 0)
        $okN = if ($useOwn) { $s.ownOk } else { $s.allOk }; $failN = if ($useOwn) { $s.ownFailed } else { $s.allFailed }
        if ($failN -gt 0) { $s.goodDays = 0 } elseif ($okN -gt 0) { $s.goodDays = [int]$s.goodDays + 1 }
        if ($s.goodDays -ge $GoodDays) { $s.state = 'stable'; $s.sinceUtc = $nowText }
        $s.ownOk = 0; $s.ownFailed = 0; $s.allOk = 0; $s.allFailed = 0
    }
    $wm = & $parse $cur.watermarkUtc; $newWm = $wm
    if ($null -ne $RunFacts) {
        $facts = @(@($RunFacts) | Where-Object { $_ } | ForEach-Object {
            $fx = $_; $fin = $null
            $fv = if ($fx -is [System.Collections.IDictionary]) { $fx['finishedUtc'] } else { $fx.finishedUtc }
            $fin = & $parse $fv
            $oc = "$(if ($fx -is [System.Collections.IDictionary]) { $fx['outcome'] } else { $fx.outcome })".Trim().ToLowerInvariant()
            $jb = "$(if ($fx -is [System.Collections.IDictionary]) { $fx['job'] } else { $fx.job })".Trim().ToLowerInvariant()
            if ($null -ne $fin -and $oc -in @('ok', 'warning', 'failed') -and $jb -ne 'pim-uplink') { [pscustomobject]@{ fin = $fin; outcome = $oc; job = $jb } }
        } | Sort-Object fin)
        foreach ($f in $facts) {
            if ($null -ne $wm -and $f.fin -le $wm) { continue }
            if ($null -eq $newWm -or $f.fin -gt $newWm) { $newWm = $f.fin }
            $d = $f.fin.ToString('yyyy-MM-dd'); $own = Get-PimScopeOfJobId -JobId $f.job
            foreach ($id in @($cur.scopes.Keys)) {
                $s = $cur.scopes[$id]
                if ($s.state -ne 'testing') { continue }
                $since = & $parse $s.sinceUtc
                if ($null -ne $since -and $f.fin -lt $since) { continue }
                if (-not "$($s.day)") { $s.day = $d }
                $cmp = [string]::CompareOrdinal($d, "$($s.day)")
                if ($cmp -lt 0) { continue }   # a late fact for a day already judged
                if ($cmp -gt 0) { & $judge $s $id; $s.day = $d; if ($s.state -ne 'testing') { continue } }
                if ($f.outcome -eq 'failed') { $s.allFailed++; if ($own -eq $id) { $s.ownFailed++ } }
                else { $s.allOk++; if ($own -eq $id) { $s.ownOk++ } }
            }
        }
    }
    # a day that has passed is judged even when no later run arrived
    foreach ($id in @($cur.scopes.Keys)) {
        $s = $cur.scopes[$id]
        if ($s.state -eq 'testing' -and "$($s.day)" -and [string]::CompareOrdinal($today, "$($s.day)") -gt 0) { & $judge $s $id; $s.day = $today }
    }
    if ($null -ne $newWm) { $cur.watermarkUtc = $newWm.ToString('o') }
    return $cur
}

function ConvertTo-PimScopeStabilityField {
    <#
      PURE. The heartbeat's `scopeStability` (lower-case keys, sorted by id, at most 40): [ { id; state = testing | stable;
      sinceUtc; version; goodDays } ]; $null when nothing is recorded (then the field is left out).
    #>
    param([AllowNull()][object]$State)
    $s = ConvertTo-PimScopeStabilityState -State $State
    if (-not $s.scopes.Count) { return $null }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($s.scopes.Keys | Sort-Object | Select-Object -First 40)) {
        $v = $s.scopes[$id]
        $list.Add([pscustomobject][ordered]@{ id = "$id"; state = "$($v.state)"; sinceUtc = "$($v.sinceUtc)"; version = "$($v.version)"; goodDays = [int]$v.goodDays })
    }
    return [object[]]$list.ToArray()
}
