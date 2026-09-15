# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
<#
  PIM4EntraPS -- ALERT FEED + recorded-send proof (REQUIREMENTS §26c / §28 [H2] +
  the [M5] residual: "stays open until the notify path proves a recorded send").

  The PUSH side of the dashboard. Two things were missing under the alerting work:
    (1) no persisted, queryable FEED of what alerts fired (when / which event / who
        was notified / whether the send was actually recorded) -- so a break-glass
        "owners notified" claim was unverifiable; and
    (2) the 'expiring-access' event was in the catalog but NOTHING dispatched it.

  This file is the PURE, offline-testable core for both. NO network here:
    - New-PimAlertRecord     : a fired-alert + recorded-send-proof record (the proof).
    - Get-PimAlertDedupeKey  : a stable key for debouncing repeat alerts.
    - Test-PimAlertDebounced : has an identical alert fired inside the debounce window?
    - Add-PimAlertToFeed     : append a record to a feed array, newest-first, bounded.
    - Select-PimAlertFeed    : filter (event/since/sentOnly) + page a feed.
    - Get-PimAlertFeedSummary: counts for the Home tile (total / unsent / per-event).
    - Get-PimExpiringAccessAlert : PURE evaluation -- expiring rows + now + window ->
                                   { fire; count; detail; items } (no I/O).
    - Read-/Write-PimAlertFeedSql  : the SQL adapter (pim.Settings['AlertFeed']) -- the only
                                   I/O; there is no feed FILE (SQL-only). The pure core above
                                   is storage-agnostic.

  The actual mail send stays in the existing channel layer (Send-PimNotifyMail /
  Send-PimManagerAlert). This core RECORDS the outcome that layer returns, so the
  feed is the durable proof of WOULD-SEND / DID-SEND -- it never sends anything
  itself. PS 5.1-safe (no ?./??, no RSA.ImportFromPem; .ToArray() not @() on
  List[object]; Set-Content not used for JSONL -- UTF8 no-BOM via .NET).
#>
Set-StrictMode -Off

# Canonical event types the feed understands (mirrors the Manager's
# $script:PimAlertEventCatalog -- kept here so the engine/scheduler can validate
# an event name without loading the Manager).
$script:PimAlertFeedEventCatalog = @('engine-failure','drift','expiring-access','break-glass')

function Get-PimAlertFeedField {
    # Read a field from a hashtable OR a PSObject, returning '' when absent. (Same
    # helper shape as PIM-Notifications so a record round-trips through JSON cleanly.)
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Item) { return '' }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return "$($Item[$Name])" }; return '' }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return "$($p.Value)" }
    return ''
}

function New-PimAlertRecord {
    # PURE: build one fired-alert + recorded-send-proof record. $SendResult is the
    # hashtable Send-PimManagerAlert returns (@{ fired; sent; recipients; reason }) --
    # we fold its outcome in so the record IS the durable proof of whether the alert
    # was delivered, rendered-only (dry-run / no sender), or suppressed. The record
    # carries NO capability -- it is data only.
    #   sendState: 'sent'      -> at least one recipient mail was recorded as sent
    #              'rendered'  -> prepared but not delivered (dry-run / no sender / no recipient)
    #              'suppressed'-> event disabled or no recipients configured (never fired)
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Title,
        [string]$Detail,
        [string]$LinkTab,
        [object]$SendResult,
        [string]$TenantName = '',
        [string]$Instance = '',
        [bool]$WhatIf = $false,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $ev = "$Event".Trim()
    $fired = $false; $sent = 0; $recipients = @(); $reason = ''
    if ($null -ne $SendResult) {
        # 'fired' is read as text (a record may round-trip through JSON), so "False"/""
        # are NOT truthy -- only an explicit true/1/yes counts as fired.
        $fired = ("$(Get-PimAlertFeedField -Item $SendResult -Name 'fired')".Trim().ToLowerInvariant() -in @('true','1','yes'))
        $sRaw = (Get-PimAlertFeedField -Item $SendResult -Name 'sent')
        if ("$sRaw".Trim() -match '^\d+$') { $sent = [int]$sRaw }
        $reason = (Get-PimAlertFeedField -Item $SendResult -Name 'reason')
        $rc = $null
        if ($SendResult -is [System.Collections.IDictionary]) { if ($SendResult.Contains('recipients')) { $rc = $SendResult['recipients'] } }
        elseif ($SendResult.PSObject.Properties['recipients']) { $rc = $SendResult.PSObject.Properties['recipients'].Value }
        if ($rc) { $recipients = @($rc | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    }
    $sendState = if ($sent -gt 0) { 'sent' } elseif ($fired) { 'rendered' } else { 'suppressed' }
    [pscustomobject]@{
        id          = [guid]::NewGuid().ToString()
        ts          = $NowUtc.ToUniversalTime().ToString('o')
        event       = $ev
        title       = "$Title"
        detail      = "$Detail"
        linkTab     = "$LinkTab"
        fired       = [bool]$fired
        sent        = [int]$sent
        recipients  = @($recipients)
        sendState   = $sendState
        reason      = "$reason"
        whatIf      = [bool]$WhatIf
        tenantName  = "$TenantName"
        instance    = "$Instance"
    }
}

function Get-PimAlertDedupeKey {
    # PURE: a stable key for an alert so identical repeats can be debounced. Built
    # from event + a normalised title + detail (lower/trim, whitespace collapsed) --
    # NOT the timestamp, so the same condition firing twice hashes the same.
    param([Parameter(Mandatory)][string]$Event, [string]$Title, [string]$Detail)
    $norm = {
        param([string]$s)
        ("$s" -replace '\s+', ' ').Trim().ToLowerInvariant()
    }
    return ("{0}|{1}|{2}" -f "$Event".Trim().ToLowerInvariant(), (& $norm $Title), (& $norm $Detail))
}

function Test-PimAlertDebounced {
    # PURE: is an alert with this dedupe key already in the feed within the debounce
    # window ending at NowUtc? Used so a recurring condition (e.g. the same drift on
    # every reconcile) does not spam -- the caller skips the send when this is $true.
    # DebounceMinutes <= 0 disables debouncing (always $false).
    param(
        [Parameter(Mandatory)][object[]]$Feed,
        [Parameter(Mandatory)][string]$DedupeKey,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$DebounceMinutes = 60
    )
    if ($DebounceMinutes -le 0) { return $false }
    $cutoff = $NowUtc.ToUniversalTime().AddMinutes(-1 * $DebounceMinutes)
    foreach ($r in @($Feed)) {
        if ($null -eq $r) { continue }
        $ev = (Get-PimAlertFeedField -Item $r -Name 'event')
        $ti = (Get-PimAlertFeedField -Item $r -Name 'title')
        $de = (Get-PimAlertFeedField -Item $r -Name 'detail')
        $k = Get-PimAlertDedupeKey -Event $ev -Title $ti -Detail $de
        if ($k -ne $DedupeKey) { continue }
        $tsRaw = (Get-PimAlertFeedField -Item $r -Name 'ts')
        $ts = Get-PimUtcStamp $tsRaw   # IMP-02
        if ($null -eq $ts) { continue }
        if ($ts -ge $cutoff) { return $true }
    }
    return $false
}

function Add-PimAlertToFeed {
    # PURE: prepend a record to a feed array (newest-first) and clamp to MaxKeep.
    # Returns the new array. Never mutates the input.
    param(
        [Parameter(Mandatory)][object]$Record,
        [object[]]$Feed = @(),
        [int]$MaxKeep = 500
    )
    $list = New-Object System.Collections.Generic.List[object]
    $list.Add($Record)
    foreach ($r in @($Feed)) { if ($null -ne $r) { $list.Add($r) } }
    if ($MaxKeep -gt 0 -and $list.Count -gt $MaxKeep) {
        $trimmed = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $MaxKeep; $i++) { $trimmed.Add($list[$i]) }
        return $trimmed.ToArray()
    }
    return $list.ToArray()
}

function Select-PimAlertFeed {
    # PURE: filter + page a feed for display. Filters: -Event (one type), -SinceUtc
    # (only newer), -SentOnly (only records that were actually delivered). Always
    # returns newest-first. -Take 0 = all.
    param(
        [object[]]$Feed = @(),
        [string]$Event,
        [Nullable[datetime]]$SinceUtc,
        [switch]$SentOnly,
        [int]$Take = 100
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Feed)) {
        if ($null -eq $r) { continue }
        if ($Event -and (Get-PimAlertFeedField -Item $r -Name 'event') -ne $Event) { continue }
        if ($SentOnly) {
            $sRaw = (Get-PimAlertFeedField -Item $r -Name 'sent'); $s = 0
            if ("$sRaw".Trim() -match '^\d+$') { $s = [int]$sRaw }
            if ($s -le 0) { continue }
        }
        if ($SinceUtc) {
            $tsRaw = (Get-PimAlertFeedField -Item $r -Name 'ts')   # IMP-02
            $ts = Get-PimUtcStamp $tsRaw
            if ($null -eq $ts) { continue }
            if ($ts -lt ([datetime]$SinceUtc).ToUniversalTime()) { continue }
        }
        $rows.Add($r)
    }
    # IMP-02: an unreadable stamp sorts as MinValue (oldest), never as "now".
    $sorted = @($rows.ToArray() | Sort-Object { $t = Get-PimUtcStamp (Get-PimAlertFeedField -Item $_ -Name 'ts'); if ($null -eq $t) { [datetime]::MinValue } else { $t } } -Descending)
    if ($Take -gt 0 -and $sorted.Count -gt $Take) { $sorted = @($sorted[0..($Take - 1)]) }
    return @($sorted)
}

function Get-PimAlertFeedSummary {
    # PURE: roll a feed into the Home-tile shape -- total, how many were actually
    # delivered vs rendered-only/suppressed (the proof headline), per-event counts,
    # and the most recent record. $WindowHours bounds "recent" (0 = whole feed).
    param([object[]]$Feed = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$WindowHours = 168)
    $since = if ($WindowHours -gt 0) { $NowUtc.ToUniversalTime().AddHours(-1 * $WindowHours) } else { [datetime]::MinValue }
    $recent = @(Select-PimAlertFeed -Feed $Feed -SinceUtc $since -Take 0)
    $byEvent = [ordered]@{}
    foreach ($e in $script:PimAlertFeedEventCatalog) { $byEvent[$e] = 0 }
    $sent = 0; $unsent = 0
    foreach ($r in $recent) {
        $ev = (Get-PimAlertFeedField -Item $r -Name 'event')
        if ($byEvent.Contains($ev)) { $byEvent[$ev] = [int]$byEvent[$ev] + 1 } else { $byEvent[$ev] = 1 }
        $sRaw = (Get-PimAlertFeedField -Item $r -Name 'sent'); $s = 0
        if ("$sRaw".Trim() -match '^\d+$') { $s = [int]$sRaw }
        if ($s -gt 0) { $sent++ } else { $unsent++ }
    }
    $latest = if ($recent.Count -gt 0) { $recent[0] } else { $null }
    [ordered]@{
        total       = $recent.Count
        sent        = $sent           # records with a recorded delivery (the proof)
        unsent      = $unsent         # fired-but-rendered-only or suppressed
        byEvent     = $byEvent
        windowHours = $WindowHours
        latest      = $(if ($latest) { [ordered]@{ ts = (Get-PimAlertFeedField -Item $latest -Name 'ts'); event = (Get-PimAlertFeedField -Item $latest -Name 'event'); title = (Get-PimAlertFeedField -Item $latest -Name 'title'); sendState = (Get-PimAlertFeedField -Item $latest -Name 'sendState') } } else { $null })
    }
}

function Get-PimExpiringAccessAlert {
    # PURE: decide whether the 'expiring-access' alert should fire, from a set of
    # active-assignment rows (each with a principal/role/end). An assignment counts
    # when its end is in [NowUtc, NowUtc + WindowDays]. Returns
    #   @{ fire; count; windowDays; detail; items }.
    # No I/O -- the caller fetches rows (Get-PimActiveAssignmentsCached) and, when
    # fire is $true and not debounced, calls Send-PimManagerAlert with the detail.
    param(
        [object[]]$Rows = @(),
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$WindowDays = 14,
        [int]$MaxItems = 12
    )
    $now = $NowUtc.ToUniversalTime()
    $soon = $now.AddDays([math]::Max(1, $WindowDays))
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $endRaw = (Get-PimAlertFeedField -Item $r -Name 'end')
        if (-not "$endRaw".Trim()) { continue }
        $end = Get-PimUtcStamp $endRaw   # IMP-02
        if ($null -eq $end) { continue }
        if ($end -lt $now -or $end -gt $soon) { continue }
        $hits.Add([pscustomobject]@{
            principal = (Get-PimAlertFeedField -Item $r -Name 'principal')
            role      = (Get-PimAlertFeedField -Item $r -Name 'role')
            endUtc    = $end.ToString('o')
            type      = (Get-PimAlertFeedField -Item $r -Name 'type')
        })
    }
    $ordered = @($hits.ToArray() | Sort-Object { [datetime]$_.endUtc })
    $count = $ordered.Count
    $items = if ($MaxItems -gt 0 -and $count -gt $MaxItems) { @($ordered[0..($MaxItems - 1)]) } else { $ordered }
    $detail = if ($count -gt 0) {
        $first = @($items | ForEach-Object { "$($_.principal) -> $($_.role) ($([datetime]$_.endUtc).ToString('yyyy-MM-dd'))" }) -join '; '
        "{0} active assignment(s) expire within {1} day(s): {2}" -f $count, $WindowDays, $first
    } else { '' }
    [ordered]@{
        fire       = ($count -gt 0)
        count      = $count
        windowDays = $WindowDays
        detail     = $detail
        items      = @($items)
    }
}

# ---------------------------------------------------------------------------
# SQL adapter (§36 phase 4). The feed is the recorded-send PROOF: it is what
# says an operator WAS notified that break-glass fired, or that a drift alert
# went out. That is evidence, not telemetry -- and on a hosted deployment it
# was being appended to a container filesystem with no persistent volume, so
# every revision roll destroyed the proof while leaving the alerts themselves
# looking fine.
#
# Stored as ONE bounded JSON document in pim.Settings rather than a table: the
# pure core above already filters, pages and summarises an in-memory array, and
# Add-PimAlertToFeed clamps the feed to MaxKeep (500). A table would mean
# reimplementing Select-PimAlertFeed in SQL for no behavioural gain.
# ---------------------------------------------------------------------------
function Get-PimAlertFeedStoreName { 'AlertFeed' }

function Read-PimAlertFeedSql {
    # Returns @() when there is no store, no value, or the value is unreadable.
    # NEVER throws: the alert feed is a display + proof surface, and a feed read
    # that takes down the Home tile would be a worse failure than a short feed.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $v = Get-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimAlertFeedStoreName)
    if (-not $v) { return @() }
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { return @() } }
    $inner = $null
    if ($v -is [System.Collections.IDictionary]) {
        if ($v.Contains('alerts')) { $inner = $v['alerts'] }
    } elseif ($v.PSObject -and $v.PSObject.Properties['alerts']) {
        $inner = $v.alerts
    }
    if ($null -eq $inner) { return @() }
    return @(Select-PimAlertFeed -Feed @($inner) -Take 0)
}

function Write-PimAlertFeedSql {
    # Prepend one record and persist the clamped feed. Read-modify-write, which is
    # correct here: the Manager is the ONLY writer (verified -- no engine, job or
    # setup path calls the feed writer), and it is a single container app, so there
    # is no concurrent-append case to lose a record to.
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][object]$Record,
        [int]$MaxKeep = 500
    )
    $cur  = @(Read-PimAlertFeedSql -ConnectionString $ConnectionString)
    $next = @(Add-PimAlertToFeed -Record $Record -Feed $cur -MaxKeep $MaxKeep)
    Set-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimAlertFeedStoreName) -Value @{ alerts = $next }
    return $next.Count
}

# The JSONL file adapter (Read-/Write-PimAlertFeedFile over output/alerts/pim-alerts.jsonl) was removed
# 2026-09-13: PIM v2 is SQL-only, and the feed is the recorded-send PROOF -- it lives in
# pim.Settings['AlertFeed'] (the SQL adapter above) and nowhere else.
