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
     does: the uplink job runs hourly, so it says 60 (the faster cadence is an open item of 100.158).
  ASCII only; PS 5.1 + 7; no module.
#>
Set-StrictMode -Off

function Get-PimReleaseControlScopeIds {
    <# PURE. The fixed scope ids (engine.<area> is open: any lower-case area name). #>
    return @('engine', 'manager', 'updater', 'scheduler', 'sql-schema', 'setup', 'activator')
}

function Get-PimReleaseModeHours { <# PURE. framework 12.11e item 3: PIM's release window, hours. #> return 4 }
function Get-PimReleaseModeEveryMinutes { <# PURE. What the uplink job really does today: hourly. #> return 60 }
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
        $d = [datetime]::MinValue
        $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
        if ("$($StrictState.sinceUtc)".Trim() -and [datetime]::TryParse("$($StrictState.sinceUtc)", [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) {
            $since = $d.ToUniversalTime(); $until = $since.AddHours((Get-PimReleaseModeHours)); $now = $NowUtc.ToUniversalTime()
            if ($now -ge $since -and $now -lt $until -and "$($StrictState.version)".Trim()) {
                $rm = [pscustomobject][ordered]@{ version = "$($StrictState.version)".Trim(); sinceUtc = $since.ToString('o'); untilUtc = $until.ToString('o'); everyMinutes = (Get-PimReleaseModeEveryMinutes) }
            }
        }
        $out['releaseMode'] = $rm
    }
    return $out
}
