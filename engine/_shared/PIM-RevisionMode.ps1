#Requires -Version 5.1
<#
.SYNOPSIS
  SEC-PATCH-PIPELINE-1 point 6 (owner 2026-11-26 via Invardia: "will an attacker see the new or old image if they try to
  attack ?"): after every swap -- the normal update AND the image-only path -- NOTHING OLD ANSWERS. The updater's LAST step
  reads every Container App of the install (ARM: properties.configuration.activeRevisionsMode, the revisions with their
  active flag and traffic weight, ingress.traffic labels) and, when an app is not Single with exactly ONE active revision at
  100 % latest and no traffic label, sets it back: activeRevisionsMode Single + traffic latestRevision 100 % (a
  read-modify-write of properties.configuration, Set-PimArmAcaAppConfiguration in PIM-ArmSetup.ps1), reads it back, and
  deactivates any other revision that still answers. The fact goes into the install's own UpdateState as 'revisions', which
  the heartbeat sends as Update.revisions { single; activeRevisions; apps; readUtc } (Invardia's ONE shape, TELEMETRY-SAME-1:
  NO app names leave).

.DESCRIPTION
  Safety (never make it worse):
    - an app whose LATEST revision is not its latest READY one (a revision that failed to start) is NOT changed: sending
      100 % to a broken revision would take the site down; it is reported (single = false) and fixed by the next swap;
    - an app still provisioning is not changed (read again next run);
    - ONLY PIM's own apps (the Manager, and an app running an image from the Manager's repository -- Select-PimRevisionOwnedApps,
      3.1.70 review F1); any other app in the resource group is never read or changed, only counted in one log line;
    - only the install's own resource group is read (the caller passes its apps); nothing is deleted -- a deactivated
      revision stays in the history;
    - every ARM call is a seam ( -ListRevisions / -Fix / -Deactivate / -ReadApp ), so the suite runs with no Azure.
  PURE except Invoke-PimRevisionModeCheck, whose Azure calls are its seams. ASCII; PS 5.1 + 7; no modules.
#>
Set-StrictMode -Off

function Get-PimRevisionField {
    <# PURE. One key of an ARM object (pscustomobject or dictionary), $null when absent. #>
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Key)) { return $Object[$Key] } else { return $null } }
    if ($Object.PSObject.Properties[$Key]) { return $Object.$Key }
    return $null
}

# ---- 3.1.71 review K1 (A2 + B3): the ROLLBACK PIN MARKER -------------------------------------------------------------------
# Every rollback writer (Update-PimContainers.ps1 -Rollback, called by the setup, the updater, the sync and an operator) adds
# the tag  pim-rollback-pin = <the app's latestRevisionName at pin time>|<utc>|<who: operator|setup|update|sync>  in the SAME
# ARM write that pins the traffic. The revision check honours a pin ONLY while that tag exists AND the app's latestRevisionName
# still equals the tag's revision. A later roll (a new image = a new, newer revision) moves latest: the pin is then STALE and
# is released (latest 100 %, tag removed). A pin WITHOUT the tag is not honoured (fixed to latest 100 %, as before 3.1.71),
# unless latest is not ready (that guard stays).
function Get-PimRollbackPinTagName { 'pim-rollback-pin' }

function New-PimRollbackPinTagValue {
    <# PURE. The tag value: <latest revision at pin time>|<utc yyyy-MM-ddTHH:mm:ssZ>|<who>. #>
    param([Parameter(Mandatory)][string]$LatestRevision, [Parameter(Mandatory)][ValidateSet('operator', 'setup', 'update', 'sync')][string]$Who, [datetime]$NowUtc = [datetime]::UtcNow)
    return ('{0}|{1}|{2}' -f "$LatestRevision".Trim(), $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture), $Who)
}

function ConvertFrom-PimRollbackPinTag {
    <# PURE. A tag value -> @{ revision; utc; who } -- $null when absent or not the shape (no revision = no marker). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $p = @($s -split '\|')
    $rev = "$($p[0])".Trim()
    if (-not $rev) { return $null }
    $who = if ($p.Count -ge 3 -and "$($p[2])".Trim()) { "$($p[2])".Trim() } else { 'unknown' }
    return @{ revision = $rev; utc = $(if ($p.Count -ge 2) { "$($p[1])".Trim() } else { '' }); who = $who }
}

function Get-PimRollbackPinTag {
    <# PURE. The marker on an ARM app object (its tags), parsed -- $null when the app carries none. #>
    param([AllowNull()][object]$App)
    return ConvertFrom-PimRollbackPinTag -Value "$(Get-PimRevisionField (Get-PimRevisionField $App 'tags') (Get-PimRollbackPinTagName))"
}

function Remove-PimRollbackPinTag {
    <# PURE. The -MutateTags of the revision check's fix (Set-PimArmAcaAppConfiguration): drops the marker from -Tags. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.IDictionary]$Tags)
    $k = Get-PimRollbackPinTagName
    if ($Tags.Contains($k)) { [void]$Tags.Remove($k) }
}

function Get-PimRevisionModeVerdict {
    <#
      PURE. ONE app as read (-App: the ARM container app; -Revisions: its revisions, as listed) -> @{ app; mode; activeRevisions;
      labels; latestFull; canFix; ok; why }:
        ok       mode Single AND at most 1 active revision AND no traffic label AND the traffic (when the app has ingress
                 traffic) is latest 100 %
        canFix   not ok, AND the latest revision is the latest READY one, AND the app is not provisioning, AND its traffic is
                 not a LIVE rollback pin (3.1.71 I1 + review K1: a -Rollback pin is honoured only while its pim-rollback-pin
                 tag names the current latest revision; operatorPin / pinnedTo / pinBy / staleTag say so)
      -Revisions $null = the revision list could not be read: never ok (unknown is not "good"), never fixed blind.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object[]]$Revisions)
    $props = Get-PimRevisionField $App 'properties'
    $cfg = Get-PimRevisionField $props 'configuration'
    $mode = "$(Get-PimRevisionField $cfg 'activeRevisionsMode')".Trim()
    $ing = Get-PimRevisionField $cfg 'ingress'
    $traffic = @(@(Get-PimRevisionField $ing 'traffic') | Where-Object { $null -ne $_ })
    $labels = @($traffic | Where-Object { "$(Get-PimRevisionField $_ 'label')".Trim() }).Count
    $latestFull = $true
    if ($traffic.Count) {
        $lt = @($traffic | Where-Object { "$(Get-PimRevisionField $_ 'latestRevision')" -match '^(?i)true$' })
        $w = 0; foreach ($t in $lt) { $n = 0; if ([int]::TryParse("$(Get-PimRevisionField $t 'weight')", [ref]$n)) { $w += $n } }
        $latestFull = ($lt.Count -ge 1 -and $w -eq 100 -and $traffic.Count -eq $lt.Count)
    }
    # 3.1.71 I1 (3.1.70 re-review B3): an OPERATOR PIN. Update-PimContainers.ps1 -Rollback reactivates an older revision and
    # writes ingress.traffic = @( @{ revisionName = <rev>; weight = 100 } ) -- a named revision, NO label, NO latestRevision
    # (ARM reads it back with latestRevision false). Setting that back to latest 100 % would bring back the very revision the
    # rollback moved away from, so a LIVE rollback pin is not changed: not ok (it counts as not single), never canFix, reported.
    # The shape: every traffic entry names a revision, carries no label, and none is latestRevision true. A split that still
    # sends weight to latest (or carries a label) is not a pin and is fixed as before. 3.1.71 review K1: the shape alone is
    # NOT enough -- the pim-rollback-pin tag must be on the app and name the CURRENT latest revision (see above).
    $pinned = @()
    if ($traffic.Count) {
        $named = @($traffic | Where-Object { "$(Get-PimRevisionField $_ 'revisionName')".Trim() -and -not "$(Get-PimRevisionField $_ 'label')".Trim() -and "$(Get-PimRevisionField $_ 'latestRevision')" -notmatch '^(?i)true$' })
        if ($named.Count -eq $traffic.Count) { $pinned = @($named | ForEach-Object { "$(Get-PimRevisionField $_ 'revisionName')".Trim() }) }
    }
    # FIXED 2026-11-26 (3.1.71 review K1): the traffic shape alone is NOT the marker any more -- the updater rolls by changing
    # the image and never touches traffic, so after a real roll a shape-only pin would hold the app on the old revision for
    # good. A pin is honoured ONLY with the pim-rollback-pin tag AND while latestRevisionName still equals the tag's revision.
    $latest = "$(Get-PimRevisionField $props 'latestRevisionName')".Trim()
    $ready = "$(Get-PimRevisionField $props 'latestReadyRevisionName')".Trim()
    $pinTag = Get-PimRollbackPinTag -App $App
    $operatorPin = ($pinned.Count -gt 0) -and ($null -ne $pinTag) -and $latest -and ($pinTag.revision -ieq $latest)
    $staleTag = ($null -ne $pinTag) -and -not $operatorPin
    $read = ($null -ne $Revisions)
    $active = if ($read) { @(@($Revisions) | Where-Object { $null -ne $_ -and "$(Get-PimRevisionField (Get-PimRevisionField $_ 'properties') 'active')" -match '^(?i)true$' }).Count } else { -1 }
    $ok = $read -and ($mode -ieq 'Single') -and $active -le 1 -and $labels -eq 0 -and $latestFull
    $prov = "$(Get-PimRevisionField $props 'provisioningState')".Trim()
    $why = @()
    if (-not $read) { $why += 'its revisions could not be read' }
    if ($mode -ine 'Single') { $why += "mode $(if ($mode) { $mode } else { '(none)' })" }
    if ($active -gt 1) { $why += "$active active revisions" }
    if ($labels) { $why += "$labels traffic label(s)" }
    if (-not $latestFull) { $why += 'traffic not 100 % latest' }
    if (-not $ok -and $staleTag) { $why += "a stale rollback pin by $($pinTag.who) (pinned at $($pinTag.revision), latest is now $(if ($latest) { $latest } else { '(none)' }))" }
    elseif (-not $ok -and $pinned.Count -and -not $operatorPin) { $why += 'pinned with no rollback marker' }
    $canFix = (-not $ok) -and (-not $operatorPin) -and $read -and $latest -and ($latest -ieq $ready) -and ($prov -notmatch '^(?i)(InProgress|Provisioning|Updating|Deleting)$')
    if (-not $ok -and -not $canFix) {
        if ($operatorPin) { $why += "traffic pinned to $($pinned -join ', ') by a rollback ($($pinTag.who)) -- not changed" }
        elseif (-not ($latest -and $latest -ieq $ready)) { $why += 'its latest revision is not ready (not changed)' }
        elseif ($prov -match '^(?i)(InProgress|Provisioning|Updating|Deleting)$') { $why += "provisioning $prov (not changed)" }
    }
    return @{ app = "$(Get-PimRevisionField $App 'name')"; mode = $mode; activeRevisions = $active; labels = $labels; latestFull = $latestFull
              latest = $latest; canFix = [bool]$canFix; ok = [bool]$ok; operatorPin = [bool]$operatorPin; pinnedTo = @($pinned)
              pinBy = $(if ($pinTag) { "$($pinTag.who)" } else { '' }); staleTag = [bool]$staleTag; why = ($why -join ', ') }
}

function Set-PimRevisionModeSingleConfig {
    <#
      PURE. The -Mutate of Set-PimArmAcaAppConfiguration: activeRevisionsMode Single and, when the app has ingress, its
      traffic = latest revision 100 % (this drops every label and every pinned revision weight). Changes -Configuration in place.
    #>
    param([Parameter(Mandatory)][object]$Configuration)
    $Configuration | Add-Member -NotePropertyName activeRevisionsMode -NotePropertyValue 'Single' -Force
    $ing = Get-PimRevisionField $Configuration 'ingress'
    if ($null -ne $ing) { $ing | Add-Member -NotePropertyName traffic -NotePropertyValue @([pscustomobject]@{ latestRevision = $true; weight = 100 }) -Force }
}

function ConvertTo-PimRevisionsFact {
    <#
      PURE. The verdicts (after any fix, as READ BACK) -> the UpdateState fact = Invardia's Update.revisions shape:
      { single = every app read is ok; activeRevisions = the HIGHEST active count on any one app (1 = good); apps = the apps
      read; readUtc }. No app read -> $null (the heartbeat then leaves the key out: unknown is never sent as good).
    #>
    param([AllowNull()][object[]]$Verdicts, [datetime]$NowUtc = [datetime]::UtcNow)
    $vs = @(@($Verdicts) | Where-Object { $null -ne $_ -and [int]$_.activeRevisions -ge 0 })
    if (-not $vs.Count) { return $null }
    $max = 0; foreach ($v in $vs) { if ([int]$v.activeRevisions -gt $max) { $max = [int]$v.activeRevisions } }
    $single = (@($vs | Where-Object { -not $_.ok }).Count -eq 0) -and (@(@($Verdicts) | Where-Object { $null -ne $_ -and [int]$_.activeRevisions -lt 0 }).Count -eq 0)
    return [ordered]@{ single = [bool]$single; activeRevisions = [int]$max; apps = [int]$vs.Count
                       readUtc = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
}

function Get-PimRevisionImageRepo {
    <# PURE. The repository half of an image reference (tag / digest removed; a registry PORT is kept). The same rule as
       PIM-ArmContainerApps.ps1 Get-PimAcaImageRepo, copied so this file stays standalone (the suite loads it alone). #>
    param([AllowEmptyString()][string]$Image = '')
    $s = "$Image".Trim()
    if (-not $s) { return '' }
    $at = $s.IndexOf('@'); if ($at -ge 0) { return $s.Substring(0, $at) }
    $slash = $s.LastIndexOf('/'); $colon = $s.LastIndexOf(':')
    if ($colon -gt $slash) { return $s.Substring(0, $colon) }
    return $s
}

function Select-PimRevisionOwnedApps {
    <#
      PURE. FIX 2026-11-26 (3.1.70 review F1): ONLY PIM'S OWN APPS are read or changed. The rule is the one the updater already
      uses for the roll (PIM-ArmContainerApps.ps1 Get-PimAcaJobRollPlan, "SAME REPOSITORY, NOT EVERY JOB"): an app is PIM's when
      it IS the Manager app (-ManagerApp, by name) or when one of its containers runs an image from the Manager's repository
      (-ManagerImage). Every other app in the resource group is a customer's -- never read, never changed, never counted in
      Update.revisions; the caller reports only HOW MANY there were. An unreadable Manager image ('') = the Manager by name only
      (narrow, never wider). Returns @{ owned = @(apps); foreign = <count>; repo }.
    #>
    param([AllowNull()][object[]]$Apps, [Parameter(Mandatory)][string]$ManagerApp, [AllowEmptyString()][string]$ManagerImage = '')
    $repo = Get-PimRevisionImageRepo -Image $ManagerImage
    $owned = New-Object System.Collections.Generic.List[object]; $foreign = 0
    foreach ($a in @(@($Apps) | Where-Object { $null -ne $_ })) {
        $name = "$(Get-PimRevisionField $a 'name')".Trim()
        $mine = ($name -and $name -ieq "$ManagerApp".Trim())
        if (-not $mine -and $repo) {
            $cs = @(Get-PimRevisionField (Get-PimRevisionField (Get-PimRevisionField $a 'properties') 'template') 'containers')
            foreach ($c in @($cs | Where-Object { $null -ne $_ })) { if ((Get-PimRevisionImageRepo -Image "$(Get-PimRevisionField $c 'image')") -ieq $repo) { $mine = $true; break } }
        }
        if ($mine) { $owned.Add($a) } else { $foreign++ }
    }
    return @{ owned = @($owned.ToArray()); foreign = [int]$foreign; repo = $repo }
}

function Invoke-PimRevisionModeCheck {
    <#
      The updater's LAST step. -Apps: the container apps of the install's resource group (ARM list objects); ONLY PIM's own
      (Select-PimRevisionOwnedApps with -ManagerApp / -ManagerImage) are read and changed -- the others are counted, one line,
      and left alone (result 'foreign'). Seams:
        -ListRevisions { param($App) } -> the app's revisions (throws / $null = unreadable)
        -Fix           { param($App) }    the read-modify-write to Single + latest 100 % (Set-PimArmAcaAppConfiguration with
                                          Set-PimRevisionModeSingleConfig as its -Mutate)
        -ReadApp       { param($App) } -> the app read again after the fix
        -Deactivate    { param($App, $RevisionName) } an active revision other than the latest that still answers after the fix
        -Log           { param($Line) }
      Returns @{ fact (ConvertTo-PimRevisionsFact of the READ-BACK state, $null = nothing read); verdicts; fixed; failed;
      lines }. Never throws.
    #>
    param([AllowNull()][object[]]$Apps, [Parameter(Mandatory)][scriptblock]$ListRevisions, [Parameter(Mandatory)][string]$ManagerApp,
          [AllowEmptyString()][string]$ManagerImage = '', [scriptblock]$Fix = $null, [scriptblock]$ReadApp = $null,
          [scriptblock]$Deactivate = $null, [scriptblock]$Log = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($l) $lines.Add("$l"); if ($Log) { try { & $Log "$l" } catch { } } }
    $final = New-Object System.Collections.Generic.List[object]; $fixed = 0; $failed = 0
    $sel = Select-PimRevisionOwnedApps -Apps $Apps -ManagerApp $ManagerApp -ManagerImage $ManagerImage
    if ($sel.foreign) { & $say "revisions: $($sel.foreign) other app(s) in the resource group are not PIM's -- not read, not changed, not counted" }
    foreach ($a in @($sel.owned)) {
        $name = "$(Get-PimRevisionField $a 'name')"
        $revs = $null; try { $revs = @(& $ListRevisions $a) } catch { $revs = $null }
        $v = Get-PimRevisionModeVerdict -App $a -Revisions $revs
        if ($v.ok) { $final.Add($v); continue }
        if ($v.operatorPin) { & $say "revisions: $name traffic is pinned to $($v.pinnedTo -join ', ') by a rollback ($($v.pinBy)) -- left pinned, counted as not single; the next roll releases it"; $final.Add($v); continue }
        # 3.1.71 review K1: a pin with a STALE marker (latest moved) or with NO marker falls through to the fix below; the fix
        # (the callers' -Fix: Set-PimArmAcaAppConfiguration -MutateTags Remove-PimRollbackPinTag) also removes the marker.
        if (-not $v.canFix -or -not $Fix) { & $say "revisions: $name is not single ($($v.why)) -- not changed"; $final.Add($v); continue }
        try {
            & $Fix $a
            $a2 = $a; if ($ReadApp) { $a2 = & $ReadApp $a; if ($null -eq $a2) { $a2 = $a } }
            $revs2 = $null; try { $revs2 = @(& $ListRevisions $a2) } catch { $revs2 = $null }
            $latest = "$(Get-PimRevisionField (Get-PimRevisionField $a2 'properties') 'latestRevisionName')".Trim()
            if ($Deactivate -and $null -ne $revs2 -and $latest) {
                foreach ($r in @($revs2 | Where-Object { $null -ne $_ -and "$(Get-PimRevisionField (Get-PimRevisionField $_ 'properties') 'active')" -match '^(?i)true$' -and "$(Get-PimRevisionField $_ 'name')" -ine $latest })) {
                    try { & $Deactivate $a2 "$(Get-PimRevisionField $r 'name')"; & $say "revisions: $name -- deactivated the old revision $(Get-PimRevisionField $r 'name')" }
                    catch { & $say "revisions: $name -- the old revision $(Get-PimRevisionField $r 'name') could not be deactivated: $((("$($_.Exception.Message)") -split "`n")[0])" }
                }
                try { $revs2 = @(& $ListRevisions $a2) } catch { $revs2 = $null }
            }
            $v2 = Get-PimRevisionModeVerdict -App $a2 -Revisions $revs2
            if ($v2.ok) { $fixed++; & $say "revisions: $name set back to Single, latest 100 % (was: $($v.why))$(if ($v.staleTag) { " -- the stale rollback pin ($($v.pinBy)) is released$(if (Get-PimRollbackPinTag -App $a2) { ', but the marker still reads back' } else { ', marker removed' })" }) -- read back ok" }
            else { $failed++; & $say "revisions: $name set to Single but it reads back $($v2.why)" }
            $final.Add($v2)
        } catch {
            $failed++; & $say "revisions: $name could not be set to Single: $((("$($_.Exception.Message)") -split "`n")[0])"
            $final.Add($v)
        }
    }
    return @{ fact = (ConvertTo-PimRevisionsFact -Verdicts @($final.ToArray()) -NowUtc $NowUtc); verdicts = @($final.ToArray()); fixed = $fixed; failed = $failed; foreign = [int]$sel.foreign; lines = @($lines.ToArray()) }
}
