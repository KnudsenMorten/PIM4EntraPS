#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 70.17 (owner decision 2026-10-29: "Delta + skip if unchanged") -- a TIMER engine-delta job is skipped
    when nothing it could act on has changed since its last clean run.

.DESCRIPTION
    Every 5-minute tick already runs the SQL change detector, and a committed change arms an engine-delta TRIGGER for only
    the changed scopes (PIM-Cutover.ps1, Invoke-PimSqlChangeDetector). Next to that, ~12 TIMER engine-delta jobs (the
    schedule in PIM-Scheduler.ps1) read the LIVE tenant for their scope every 5-30 minutes even when nothing changed. This
    file decides, for ONE scheduled run of ONE such job, whether that read can be skipped.

    A timer run is SKIPPED ("[cadence] SKIPPED: unchanged -- ...") only when ALL of these hold:
      1. the switch is on (pim.Settings 'DeltaSkipPolicy'.enabled; ON by default -- the owner's choice);
      2. the job's last REAL scheduled run is recorded (pim.Settings 'DeltaSkipState:<job>') for the SAME scope set and the
         SAME running version;
      3. that run converged CLEANLY: ok, ran, nothing held, nothing waiting, no scope NOT CHECKED, no warning, not WhatIf;
      4. the scope's DESIRED-STATE SIGNATURE is readable and equal to the one taken before that run (COUNT + MAX(UpdatedUtc)
         per pim.Rows entity -- the same signal the verify-convergence cache and the change detector use). The signature
         covers the entities that feed the job's scopes (the change detector's entity -> scope map) PLUS every
         'PIM-Definitions-*' / 'Account-Definitions-*' entity; a scope the map does not name hashes EVERY entity;
      5. no item of its scopes is in the currently-failing set (pim.Settings 'EngineItemFailures');
      6. no Remove row of its entities waits for its confirming second read (pim.Settings 'RemoveRowAbsentSeen');
      7. the DRIFT SWEEP is not due: the last real run started less than 'DeltaSkipPolicy'.driftSweepHours ago (default 4,
         1..24) -- an out-of-band tenant change (a portal edit) is invisible to the desired signature, so every scope is
         still read for real at least that often;
      8. no DATE-DRIVEN work is due (Get-PimDeltaSkipDateDue): an admin ProvisionDate / AutoDisableDate (OffboardDate) /
         TAP lead window crossed since the last run, an AutoExtend whose lead window is reached, or a time-limited
         assignment that ended since the last run (the engine's own upcoming list, pim.Settings 'AutoExtendOutlook').
    Anything that cannot be READ counts as "changed": the run happens. Never skipped at all: the daily full-reconcile
    (engine-full), triggers (commits, Run now, the change detector), a selection-limited run, a WhatIf plan.

    PURE except Get-PimDeltaSkipVerdict / Get-PimDeltaSkipState / Save-PimDeltaSkipRunState / Get-PimDeltaSkipPolicy,
    whose reads go through functions an offline test stubs (Get-PimSetting / Set-PimSetting, Get-PimSqlEntitySignatures,
    Get-PimSqlRows, Get-PimEngineItemFailures). No module, no az, no Graph. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimDeltaSkipLimits {
    <# PURE. LITERAL. The bounds of 'DeltaSkipPolicy' (a literal, never a $script: default -- BUG-79-6b). #>
    return [pscustomobject]@{ defaultEnabled = $true; defaultDriftSweepHours = 4; minDriftSweepHours = 1; maxDriftSweepHours = 24; settingName = 'DeltaSkipPolicy' }
}

function Get-PimDeltaSkipStateName {
    param([Parameter(Mandatory)][string]$JobName)
    $n = "$JobName".Trim(); if ($n.Length -gt 160) { $n = $n.Substring(0, 160) }
    return "DeltaSkipState:$n"
}

function ConvertTo-PimDeltaSkipUtc {
    # PURE. A stamp (ISO text, or the [datetime] pwsh 7's ConvertFrom-Json makes of one) -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $st = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function Format-PimDeltaSkipText {
    # PURE. String.Format with the INVARIANT culture: a stamp in a reason reads the same on every host (never '10.29.2026 14.00').
    param([Parameter(Mandatory)][string]$Format, [object[]]$Arguments = @())
    return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, $Format, [object[]]$Arguments)
}

function Get-PimDeltaSkipField {
    param($O, [string]$N)
    if ($null -eq $O) { return $null }
    if ($O -is [System.Collections.IDictionary]) { foreach ($k in @($O.Keys)) { if ("$k" -ieq $N) { return $O[$k] } }; return $null }
    $p = $O.PSObject.Properties[$N]; if ($p) { return $p.Value }
    return $null
}

function ConvertFrom-PimDeltaSkipJson {
    # A stored value (JSON text -- possibly double-encoded -- or already parsed) -> object; $null when blank.
    # Throws on text that is not JSON: the caller decides what "unreadable" means for it.
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        if (-not "$v".Trim()) { return $null }
        $v = $v | ConvertFrom-Json
    }
    return $v
}

function ConvertTo-PimDeltaSkipPolicy {
    <#
      PURE. pim.Settings 'DeltaSkipPolicy' -> @{ enabled; driftSweepHours; note }. Nothing stored = ON, 4 hours.
      enabled: only an explicit off word (false / 0 / no / off) switches the skip off. driftSweepHours: a whole number,
      clamped to 1..24; anything else = the default 4 (with a note). Never a guess wider than the bounds.
    #>
    param([AllowNull()][object]$Value)
    $lim = Get-PimDeltaSkipLimits
    $out = [ordered]@{ enabled = [bool]$lim.defaultEnabled; driftSweepHours = [int]$lim.defaultDriftSweepHours; note = 'default' }
    $v = $null
    try { $v = ConvertFrom-PimDeltaSkipJson $Value } catch { $out.note = 'the stored DeltaSkipPolicy is not readable JSON -- the defaults apply'; return [pscustomobject]$out }
    if ($null -eq $v) { return [pscustomobject]$out }
    $out.note = 'stored'
    $en = Get-PimDeltaSkipField $v 'enabled'
    if ($null -ne $en) {
        if ($en -is [bool]) { $out.enabled = [bool]$en }
        elseif ("$en".Trim() -match '^(?i)(false|0|no|off)$') { $out.enabled = $false }
        elseif ("$en".Trim() -match '^(?i)(true|1|yes|on)$') { $out.enabled = $true }
    }
    $h = Get-PimDeltaSkipField $v 'driftSweepHours'
    if ($null -ne $h -and "$h".Trim()) {
        $n = 0
        if ($h -isnot [bool] -and [int]::TryParse("$h".Trim(), [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
            if ($n -lt $lim.minDriftSweepHours) { $out.driftSweepHours = [int]$lim.minDriftSweepHours; $out.note = "driftSweepHours $n is below $($lim.minDriftSweepHours) -- $($lim.minDriftSweepHours) is used" }
            elseif ($n -gt $lim.maxDriftSweepHours) { $out.driftSweepHours = [int]$lim.maxDriftSweepHours; $out.note = "driftSweepHours $n is above $($lim.maxDriftSweepHours) -- $($lim.maxDriftSweepHours) is used" }
            else { $out.driftSweepHours = $n }
        } else { $out.note = "driftSweepHours '$h' is not a whole number -- the default $($lim.defaultDriftSweepHours) is used" }
    }
    return [pscustomobject]$out
}

function Get-PimDeltaSkipPolicy {
    <#
      The policy for THIS run. Order: $global:PIM_DeltaSkipPolicy (a process override) -> pim.Settings (Get-PimSetting) ->
      the hydrated $global:PIM_NamingConventions -> the default. A store read that THROWS = the skip is OFF for this run
      (fail safe: an unreadable switch never stops a read).
    #>
    $name = (Get-PimDeltaSkipLimits).settingName
    if ($null -ne $global:PIM_DeltaSkipPolicy -and "$($global:PIM_DeltaSkipPolicy)".Trim()) { return (ConvertTo-PimDeltaSkipPolicy -Value $global:PIM_DeltaSkipPolicy) }
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        $raw = $null
        try { $raw = Get-PimSetting -Name $name }
        catch { return [pscustomobject]@{ enabled = $false; driftSweepHours = [int](Get-PimDeltaSkipLimits).defaultDriftSweepHours; note = "the setting could not be read ($($_.Exception.Message)) -- not skipping" } }
        if ($null -ne $raw) { return (ConvertTo-PimDeltaSkipPolicy -Value $raw) }
    }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($name)) {
        return (ConvertTo-PimDeltaSkipPolicy -Value $global:PIM_NamingConventions[$name])
    }
    return (ConvertTo-PimDeltaSkipPolicy -Value $null)
}

function Get-PimDeltaSkipGroupDefinitionScopes { return @('groups', 'administrativeunitmembers', 'groupowners', 'groupspolicies') }
function Get-PimDeltaSkipAdminScopes { return @('admins', 'admintap', 'adminmembers', 'adminoffboarding') }
function Get-PimDeltaSkipAssignmentKindScopes {
    # PURE. LITERAL. AutoExtend outlook kind (Get-PimAutoExtendRowKind) -> the canonical scope that applies that row.
    return @{ admins = 'adminmembers'; groups = 'groupmembers'; roles = 'entraroles'; rolesaus = 'rolesaus'; direct = 'entrarolesdirect'; azure = 'azres' }
}

function Test-PimDeltaSkipDefinitionEntity {
    param([string]$Entity)
    return ("$Entity" -like 'PIM-Definitions-*' -or "$Entity" -like 'Account-Definitions-*')
}

function Get-PimDeltaSkipScopeEntities {
    <#
      PURE. Which pim.Rows entities can change what the job's scopes do? -> @{ all; entities; unmapped }.
      -EntityScopeMap is the change detector's map (Get-PimEntityScopeMap: entity -> scopes). A scope NOTHING in the map
      names (and not one of the group-definition scopes) makes the answer ALL entities: a gap in the map costs a read,
      never a skip. Every definition entity is always included (a group / admin definition change can move any scope).
      -Entities: the entity names present now (the keys of the signature map).
    #>
    param([string[]]$ScopeKeys = @(), [AllowNull()][object]$EntityScopeMap, [string[]]$Entities = @())
    $keys = @(@($ScopeKeys) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $defScopes = Get-PimDeltaSkipGroupDefinitionScopes
    $covered = @{}
    $wanted = @{}
    if ($null -ne $EntityScopeMap) {
        $pairs = @()
        if ($EntityScopeMap -is [System.Collections.IDictionary]) { foreach ($k in @($EntityScopeMap.Keys)) { $pairs += ,@("$k", @($EntityScopeMap[$k])) } }
        else { foreach ($p in @($EntityScopeMap.PSObject.Properties)) { $pairs += ,@("$($p.Name)", @($p.Value)) } }
        foreach ($pr in $pairs) {
            $targets = @(@($pr[1]) | ForEach-Object { "$_".Trim().ToLowerInvariant() })
            $hit = @($targets | Where-Object { $keys -contains $_ })
            foreach ($h in $hit) { $covered[$h] = $true }
            if ($hit.Count) { $wanted["$($pr[0])".ToLowerInvariant()] = $true }
        }
    }
    foreach ($k in $keys) { if ($defScopes -contains $k) { $covered[$k] = $true } }
    $unmapped = @($keys | Where-Object { -not $covered.ContainsKey($_) })
    $all = ($null -eq $EntityScopeMap -or $unmapped.Count -gt 0 -or $keys.Count -eq 0)
    $ents = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Entities | Sort-Object -Unique)) {
        $en = "$e".Trim(); if (-not $en) { continue }
        if ($all -or (Test-PimDeltaSkipDefinitionEntity $en) -or $wanted.ContainsKey($en.ToLowerInvariant())) { $ents.Add($en) }
    }
    return [pscustomobject]@{ all = [bool]$all; entities = @($ents.ToArray()); unmapped = @($unmapped); mappedEntities = @($wanted.Keys) }
}

function Get-PimDeltaSkipSignature {
    <#
      PURE. The desired-state signature of a job's scopes: SHA-256 over the running version, the scope keys and the
      per-entity signatures (COUNT + MAX(UpdatedUtc), Get-PimSqlEntitySignatures) of the entities that feed them.
      '' when -EntitySignatures is $null (unreadable): the caller MUST treat '' as "unknown, so run" -- never "unchanged".
      An entity appearing or disappearing changes the signature too.
    #>
    param([string[]]$ScopeKeys = @(), [AllowNull()][object]$EntitySignatures, [AllowNull()][object]$EntityScopeMap, [string]$Version = '')
    if ($null -eq $EntitySignatures) { return [pscustomobject]@{ signature = ''; all = $true; entities = @() } }
    $map = @{}
    if ($EntitySignatures -is [System.Collections.IDictionary]) { foreach ($k in @($EntitySignatures.Keys)) { $map["$k"] = "$($EntitySignatures[$k])" } }
    else { foreach ($p in @($EntitySignatures.PSObject.Properties)) { $map["$($p.Name)"] = "$($p.Value)" } }
    $sel = Get-PimDeltaSkipScopeEntities -ScopeKeys $ScopeKeys -EntityScopeMap $EntityScopeMap -Entities @($map.Keys)
    $keys = @(@($ScopeKeys) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("v=$Version|s=$($keys -join ',')|all=$([int]$sel.all)")
    foreach ($e in @($sel.entities | Sort-Object)) { [void]$sb.Append("|$e=$($map[$e])") }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString())) } finally { $sha.Dispose() }
    $hex = -join @($bytes | ForEach-Object { $_.ToString('x2') })
    return [pscustomobject]@{ signature = $hex; all = [bool]$sel.all; entities = @($sel.entities) }
}

function ConvertTo-PimDeltaSkipCellUtc {
    # PURE-ish. A lifecycle cell (a date expression or an ISO stamp) -> UTC [datetime], or $null (blank / unreadable).
    # The engine's own resolver when it is loaded (the same answer the provider gets), else a plain invariant parse.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return (ConvertTo-PimDeltaSkipUtc $Value) }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    if (Get-Command ConvertTo-PimAdminLifecycleUtc -ErrorAction SilentlyContinue) {
        try { $r = ConvertTo-PimAdminLifecycleUtc -Value $s; if ($r.parsed) { return ([datetime]$r.utc).ToUniversalTime() }; return $null } catch { }
    }
    return (ConvertTo-PimDeltaSkipUtc $s)
}

function Get-PimDeltaSkipDateDue {
    <#
      PURE. Is DATE-DRIVEN work due for the job's scopes, given what the last real run already saw? -> @{ due; reason }.
      A moment counts when it falls in (LastRunUtc, NowUtc + 2 min] -- crossed since the last real run STARTED (that run
      evaluated every moment up to its own start, and the providers judge with a clock at or after it), with the 60 s the
      Admins provider allows for "Now" plus a margin:
        admin scopes (Admins, AdminTap, AdminMembers, AdminOffboarding), from the admin definition rows:
          ProvisionDate, AutoDisableDate (legacy OffboardDate), TAPStartDate minus the TAP lead window (-TapLeadHours)
        assignment scopes, from the engine's upcoming list ('AutoExtendOutlook' items, Add-PimAutoExtendOutlookItem):
          an assignment that ENDED in that window (time-limited access lapsed), and -- while it is still listed -- an
          AutoExtend whose lead window is reached (the item leaves the list when the extension is done)
      An unreadable cell is NOT date work (the engine itself treats it as static: provision now / never disable / TAP at
      once). Unreadable INPUTS (-AdminRowsUnreadable / -OutlookUnreadable) for a scope that needs them = due (fail safe).
    #>
    param([string[]]$ScopeKeys = @(), [object[]]$AdminRows = @(), [object[]]$Outlook = @(), [AllowNull()][object]$LastRunUtc,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$TapLeadHours = 48, [switch]$AdminRowsUnreadable, [switch]$OutlookUnreadable)
    $keys = @(@($ScopeKeys) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $now = $NowUtc.ToUniversalTime()
    $last = ConvertTo-PimDeltaSkipUtc $LastRunUtc
    if ($null -eq $last) { return [pscustomobject]@{ due = $true; reason = 'no last run to compare the dates with' } }
    $from = $last; $to = $now.AddMinutes(2)
    $inWin = { param($m) ($null -ne $m -and $m -gt $from -and $m -le $to) }
    $adminHit = @($keys | Where-Object { (Get-PimDeltaSkipAdminScopes) -contains $_ })
    if ($adminHit.Count) {
        if ($AdminRowsUnreadable) { return [pscustomobject]@{ due = $true; reason = 'the admin definitions could not be read' } }
        foreach ($r in @($AdminRows)) {
            if ($null -eq $r) { continue }
            $who = "$(Get-PimDeltaSkipField $r 'UserPrincipalName')"; if (-not $who.Trim()) { $who = "$(Get-PimDeltaSkipField $r 'Username')" }
            $pv = Get-PimDeltaSkipField $r 'ProvisionDate'; if ($null -eq $pv -or -not "$pv".Trim()) { $pv = Get-PimDeltaSkipField $r 'ProvisionUtc' }
            $m = ConvertTo-PimDeltaSkipCellUtc $pv
            if (& $inWin $m) { return [pscustomobject]@{ due = $true; reason = (Format-PimDeltaSkipText "ProvisionDate of {0} reached at {1:yyyy-MM-dd HH:mm}Z" @($who, $m)) } }
            $adv = $null
            if (Get-Command Get-PimAdminAutoDisableDate -ErrorAction SilentlyContinue) { try { $adv = (Get-PimAdminAutoDisableDate -Row $r).value } catch { $adv = $null } }
            if ($null -eq $adv -or -not "$adv".Trim()) { $adv = Get-PimDeltaSkipField $r 'AutoDisableDate'; if ($null -eq $adv -or -not "$adv".Trim()) { $adv = Get-PimDeltaSkipField $r 'OffboardDate' } }
            $m = ConvertTo-PimDeltaSkipCellUtc $adv
            if (& $inWin $m) { return [pscustomobject]@{ due = $true; reason = (Format-PimDeltaSkipText "AutoDisableDate of {0} reached at {1:yyyy-MM-dd HH:mm}Z" @($who, $m)) } }
            $tv = Get-PimDeltaSkipField $r 'TAPStartDate'; if ($null -eq $tv -or -not "$tv".Trim()) { $tv = Get-PimDeltaSkipField $r 'TapStartDate' }
            $m = ConvertTo-PimDeltaSkipCellUtc $tv
            if ($null -ne $m) {
                $leadH = [Math]::Max(0, $TapLeadHours)
                $issueAt = $m.AddHours(-1 * $leadH)
                if (& $inWin $issueAt) { return [pscustomobject]@{ due = $true; reason = (Format-PimDeltaSkipText "the TAP lead window of {0} opened at {1:yyyy-MM-dd HH:mm}Z" @($who, $issueAt)) } }
            }
        }
    }
    $kindMap = Get-PimDeltaSkipAssignmentKindScopes
    $assignScopes = @($kindMap.Values)
    $assignHit = @($keys | Where-Object { $assignScopes -contains $_ })
    if ($assignHit.Count) {
        if ($OutlookUnreadable) { return [pscustomobject]@{ due = $true; reason = 'the upcoming-expiry list (AutoExtendOutlook) could not be read' } }
        foreach ($i in @($Outlook)) {
            if ($null -eq $i) { continue }
            $kind = "$(Get-PimDeltaSkipField $i 'kind')".Trim().ToLowerInvariant()
            $scope = if ($kindMap.ContainsKey($kind)) { $kindMap[$kind] } else { '' }
            if ($scope -and $keys -notcontains $scope) { continue }   # an unknown kind concerns every assignment scope
            $end = ConvertTo-PimDeltaSkipUtc (Get-PimDeltaSkipField $i 'endUtc')
            if ($null -eq $end) { return [pscustomobject]@{ due = $true; reason = "an upcoming expiry has no readable end ($(Get-PimDeltaSkipField $i 'key'))" } }
            $what = "$(Get-PimDeltaSkipField $i 'principal') $(Get-PimDeltaSkipField $i 'target')".Trim()
            if (& $inWin $end) { return [pscustomobject]@{ due = $true; reason = (Format-PimDeltaSkipText "a time-limited assignment ended at {0:yyyy-MM-dd HH:mm}Z ({1})" @($end, $what)) } }
            $we = Get-PimDeltaSkipField $i 'willExtend'
            $will = ($we -is [bool] -and $we) -or ("$we".Trim() -match '^(?i)(true|1)$')
            if ($will -and $end -gt $now) {
                $lead = 90
                $ed = ConvertTo-PimDeltaSkipUtc (Get-PimDeltaSkipField $i 'endDate'); $xd = ConvertTo-PimDeltaSkipUtc (Get-PimDeltaSkipField $i 'extendOnUtc')
                if ($null -ne $ed -and $null -ne $xd) { $lead = [int][Math]::Round(($ed - $xd).TotalDays) }
                $extendAt = $end.AddDays(-$lead)
                # one day early: the engine rounds the days left (Get-PimAssignmentMaintenance), so it may extend up to half a day sooner
                if ($now -ge $extendAt.AddDays(-1)) { return [pscustomobject]@{ due = $true; reason = (Format-PimDeltaSkipText "an AutoExtend is due (ends {0:yyyy-MM-dd}, extends from {1:yyyy-MM-dd}) ({2})" @($end, $extendAt, $what)) } }
            }
        }
    }
    return [pscustomobject]@{ due = $false; reason = 'no date-driven work due' }
}

function Get-PimDeltaSkipDecision {
    <#
      PURE. Skip THIS scheduled run of an engine-delta job? -> @{ skip; code; reason }. The order is from "cannot know" to
      "nothing to do"; the first rule that says RUN wins. Codes: off, no-scope, first, scope-changed, version, unclean,
      signature-unknown, changed, failing, pending-remove, no-last-run, drift-sweep, date-due, unchanged (the only skip).
    #>
    param([string[]]$ScopeKeys = @(), [Parameter(Mandatory)][object]$Policy, [AllowNull()][object]$State, [string]$Signature = '',
          [string]$Version = '', [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$FailingScopes = @(), [bool]$PendingRemove = $false,
          [AllowNull()][object]$DateDue = $null)
    $run = { param($c, $why) [pscustomobject]@{ skip = $false; code = $c; reason = $why } }
    $keys = @(@($ScopeKeys) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Policy.enabled) { return (& $run 'off' 'skip-if-unchanged is switched off (DeltaSkipPolicy)') }
    if (-not $keys.Count) { return (& $run 'no-scope' 'the job resolves to no engine scope') }
    if ($null -eq $State) { return (& $run 'first' 'no earlier run of this job is recorded') }
    if ("$(Get-PimDeltaSkipField $State 'scopes')" -ne ($keys -join ',')) { return (& $run 'scope-changed' 'the job''s scopes differ from its last recorded run') }
    if ("$(Get-PimDeltaSkipField $State 'version')" -ne "$Version") { return (& $run 'version' 'the running version differs from the last run''s') }
    $cl = Get-PimDeltaSkipField $State 'clean'
    if (-not ($cl -is [bool] -and $cl) -and "$cl".Trim() -notmatch '^(?i)true$') { return (& $run 'unclean' 'the last run did not converge cleanly (failed, held, waiting or not checked)') }
    if (-not "$Signature".Trim()) { return (& $run 'signature-unknown' 'the desired-state signature could not be read') }
    if ("$(Get-PimDeltaSkipField $State 'signature')" -ne "$Signature") { return (& $run 'changed' 'the desired state changed since the last run') }
    $fail = @(@($FailingScopes) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $keys -contains $_ } | Sort-Object -Unique)
    if ($fail.Count) { return (& $run 'failing' "items are still failing in [$($fail -join ', ')]") }
    if ($PendingRemove) { return (& $run 'pending-remove' 'a Remove row waits for its confirming second read') }
    $last = ConvertTo-PimDeltaSkipUtc (Get-PimDeltaSkipField $State 'startedUtc')
    if ($null -eq $last) { return (& $run 'no-last-run' 'the last run''s start time is not readable') }
    $hours = [int]$Policy.driftSweepHours
    if (($NowUtc.ToUniversalTime() - $last).TotalHours -ge $hours) { return (& $run 'drift-sweep' (Format-PimDeltaSkipText "the drift sweep is due (last real read {0:yyyy-MM-dd HH:mm}Z, every {1} h)" @($last, $hours))) }
    if ($null -eq $DateDue) { return (& $run 'date-due' 'the date-driven work could not be evaluated') }
    if ($DateDue.due) { return (& $run 'date-due' "$($DateDue.reason)") }
    return [pscustomobject]@{ skip = $true; code = 'unchanged'
        reason = (Format-PimDeltaSkipText "desired state unchanged since the clean run at {0:yyyy-MM-dd HH:mm}Z, nothing failing or waiting, no date-driven work due; the next real read is due by {1:yyyy-MM-dd HH:mm}Z (drift sweep every {2} h)" @($last, $last.AddHours($hours), $hours)) }
}

function Get-PimDeltaSkipConnectionString {
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnStringVault)".Trim())) {
        try { return "$(Get-PimSqlConnectionString)" } catch { return '' }
    }
    return ''
}

function Get-PimDeltaSkipState {
    <# The last real scheduled run of -JobName as recorded, or $null (nothing / unreadable -- both mean "run"). #>
    param([Parameter(Mandatory)][string]$JobName)
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return $null }
    try { return (ConvertFrom-PimDeltaSkipJson (Get-PimSetting -Name (Get-PimDeltaSkipStateName -JobName $JobName))) } catch { return $null }
}

function Test-PimDeltaSkipRunClean {
    <# PURE. The dispatch result of a real engine run: clean = ok, ran, not held / waiting / WhatIf (Test-PimEngineRunClean), no scope NOT CHECKED, no warning. #>
    param([AllowNull()][object]$Result)
    if (-not (Get-Command Test-PimEngineRunClean -ErrorAction SilentlyContinue)) { return $false }
    if (-not (Test-PimEngineRunClean -Result $Result)) { return $false }
    $in = $Result.result
    if ($in.PSObject.Properties['notChecked'] -and @(@($in.notChecked) | Where-Object { "$_".Trim() }).Count) { return $false }
    if ($in.PSObject.Properties['warning'] -and $in.warning) { return $false }
    return $true
}

function Save-PimDeltaSkipRunState {
    <#
      After a REAL scheduled run: record the signature taken BEFORE it (so a commit made while it ran is seen as a change
      next time), its start, whether it was clean, its scopes and version. Never throws -- a state that is not saved only
      means the next run is not skipped.
    #>
    param([Parameter(Mandatory)][object]$Job, [AllowNull()][object]$Verdict, [AllowNull()][object]$Result, [datetime]$StartedUtc = [datetime]::UtcNow)
    if ($null -eq $Verdict -or -not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return $false }
    try {
        $st = [ordered]@{
            scopes     = "$($Verdict.scopes)"
            signature  = "$($Verdict.signature)"
            version    = "$($Verdict.version)"
            startedUtc = $StartedUtc.ToUniversalTime().ToString('o')
            clean      = [bool](Test-PimDeltaSkipRunClean -Result $Result)
            savedUtc   = [datetime]::UtcNow.ToString('o')
        }
        Set-PimSetting -Name (Get-PimDeltaSkipStateName -JobName "$($Job.name)") -Value (ConvertTo-Json -InputObject $st -Compress) | Out-Null
        return $true
    } catch {
        Write-Warning "[cadence] the skip state of '$($Job.name)' was not saved ($($_.Exception.Message)) -- its next run is not skipped"
        return $false
    }
}

function Get-PimDeltaSkipVerdict {
    <#
      The decision for ONE scheduled engine-delta run, with the inputs read from the store. Returns the decision plus what a
      run must record afterwards: @{ skip; code; reason; signature; scopes; version; policy }. Never throws: any error = run.
    #>
    param([Parameter(Mandatory)][object]$Job, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{ skip = $false; code = ''; reason = ''; signature = ''; scopes = ''; version = ''; policy = $null }
    try {
        if ("$($Job.type)" -ne 'engine-delta') { $out.code = 'not-delta'; $out.reason = 'only a timer engine-delta job is ever skipped'; return [pscustomobject]$out }
        if ($Job.PSObject.Properties['changes'] -and @($Job.changes).Count) { $out.code = 'selection'; $out.reason = 'a selection-limited run always runs'; return [pscustomobject]$out }
        $pol = Get-PimDeltaSkipPolicy; $out.policy = $pol
        if (-not $pol.enabled) { $out.code = 'off'; $out.reason = "skip-if-unchanged is switched off ($($pol.note))"; return [pscustomobject]$out }
        $keys = @()
        if (Get-Command Get-PimEngineJobScopeKeys -ErrorAction SilentlyContinue) { $keys = @(Get-PimEngineJobScopeKeys -Job $Job) }
        $out.scopes = (@($keys | Sort-Object -Unique) -join ',')
        $ver = ''; if (Get-Command Get-PimRunningVersion -ErrorAction SilentlyContinue) { try { $ver = "$(Get-PimRunningVersion)" } catch { $ver = '' } }
        $out.version = $ver
        $cs = Get-PimDeltaSkipConnectionString
        $sigs = $null
        if ($cs -and (Get-Command Get-PimSqlEntitySignatures -ErrorAction SilentlyContinue)) { try { $sigs = Get-PimSqlEntitySignatures -ConnectionString $cs } catch { $sigs = $null } }
        $emap = $null; if (Get-Command Get-PimEntityScopeMap -ErrorAction SilentlyContinue) { try { $emap = Get-PimEntityScopeMap } catch { $emap = $null } }
        $sg = Get-PimDeltaSkipSignature -ScopeKeys $keys -EntitySignatures $sigs -EntityScopeMap $emap -Version $ver
        $out.signature = "$($sg.signature)"
        $state = Get-PimDeltaSkipState -JobName "$($Job.name)"
        $failing = @()
        if (Get-Command Get-PimEngineItemFailures -ErrorAction SilentlyContinue) { try { $failing = @(@(Get-PimEngineItemFailures) | ForEach-Object { "$($_.scope)" }) } catch { $failing = @($keys) } }
        $pendingRemove = $false
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
            try {
                $ra = ConvertFrom-PimDeltaSkipJson (Get-PimSetting -Name 'RemoveRowAbsentSeen')
                $rk = @(); if ($ra -is [System.Collections.IDictionary]) { $rk = @($ra.Keys) } elseif ($null -ne $ra) { $rk = @($ra.PSObject.Properties | ForEach-Object { $_.Name }) }
                foreach ($k in $rk) {
                    $ent = ("$k" -split '\|', 2)[0]
                    if ($sg.all -or @($sg.entities | Where-Object { "$_" -ieq $ent }).Count) { $pendingRemove = $true; break }
                }
            } catch { $pendingRemove = $true }
        }
        $dateDue = $null
        if ($null -ne $state) {
            $adminRows = @(); $adminBad = $false
            if (@($keys | Where-Object { (Get-PimDeltaSkipAdminScopes) -contains $_ }).Count) {
                if ($cs -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
                    try { foreach ($e in @('Account-Definitions-Admins', 'Account-Definitions-Admins-Central')) { $adminRows += @(Get-PimSqlRows -ConnectionString $cs -Entity $e) } } catch { $adminBad = $true }
                } else { $adminBad = $true }
            }
            $outlook = @(); $outlookBad = $false
            if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
                try { $ol = ConvertFrom-PimDeltaSkipJson (Get-PimSetting -Name 'AutoExtendOutlook'); if ($null -ne $ol) { $outlook = @(Get-PimDeltaSkipField $ol 'items') } } catch { $outlookBad = $true }
            } else { $outlookBad = $true }
            $lead = 48; if (Get-Command Get-PimAdminTapLeadHours -ErrorAction SilentlyContinue) { try { $lead = [int](Get-PimAdminTapLeadHours) } catch { $lead = 48 } }
            $dateDue = Get-PimDeltaSkipDateDue -ScopeKeys $keys -AdminRows $adminRows -Outlook $outlook -LastRunUtc (Get-PimDeltaSkipField $state 'startedUtc') -NowUtc $NowUtc `
                         -TapLeadHours $lead -AdminRowsUnreadable:$adminBad -OutlookUnreadable:$outlookBad
        }
        $d = Get-PimDeltaSkipDecision -ScopeKeys $keys -Policy $pol -State $state -Signature $out.signature -Version $ver -NowUtc $NowUtc `
                 -FailingScopes $failing -PendingRemove $pendingRemove -DateDue $dateDue
        $out.skip = [bool]$d.skip; $out.code = "$($d.code)"; $out.reason = "$($d.reason)"
    } catch {
        $out.skip = $false; $out.code = 'error'; $out.reason = "the skip check failed ($($_.Exception.Message)) -- running"
    }
    return [pscustomobject]$out
}
