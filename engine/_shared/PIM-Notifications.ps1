<#
  PIM4EntraPS -- notification BATCH logic (REQUIREMENTS §12): pure aggregation +
  render-prep for the four notification features, plus the secure ServiceNow->Manager
  inbound intake broker. NO network here -- every function is a pure transform
  (events/rows/now -> tokens / decision / store record) so the whole batch is unit
  testable offline. The actual send is the existing channel layer
  (Send-PimNotifyMail / Send-PimTemplatedMail), wired by the scheduler handlers.

  Dot-sourced by PIM-Functions.psm1 (after PIM-Approvals.ps1 / PIM-Lifecycle.ps1 /
  PIM-ChangeQueue.ps1) and standalone by the scheduler / pim-manager.

  TWO-APPROVAL MODEL (REQUIREMENTS §25, §12):
    The engine notifies on DELEGATION / ASSIGNMENT lifecycle only (new admin, new
    delegation, removal, daily summary of those, delegation-approval escalation).
    ACTIVATION emails are Entra-PIM-native and are NEVER produced here. The
    aggregation deliberately filters activation events out of the summary, and the
    escalation path covers DELEGATION approvals only.

  Features:
    (1) Daily summary    -> Get-PimDailySummary / ConvertTo-PimDailySummaryTokens
    (2) Tier 0/1 report  -> Get-PimTierZeroOneReport / ConvertTo-PimTierReportTokens
    (3) Escalation/remind -> Get-PimApprovalEscalationTargets (serial step + parallel any-one)
    (4) ServiceNow intake -> ConvertTo-PimIntakeRecord / Test-PimIntakeAccepted /
                             Resolve-PimIntakeRouting / Read-/Write-PimIntakeStore (store-and-forward)
#>
Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
function Get-PimNotifyField {
    # Read a field from a hashtable OR a PSObject, returning '' when absent.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Item) { return '' }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return "$($Item[$Name])" }; return '' }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return "$($p.Value)" }
    return ''
}

function ConvertTo-PimHtmlEncoded {
    # PURE, dependency-free HTML encoding (no System.Web needed -- works headless / in
    # the container on PS 5.1). Escapes & < > " in that order.
    param([string]$Text)
    if (-not $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

# ---------------------------------------------------------------------------
# (1) DAILY SUMMARY of PIM changes (new admins / delegations / removals)
# ---------------------------------------------------------------------------

# DELEGATION/ASSIGNMENT lifecycle actions the engine MAY summarise. Activation
# actions (handled natively by Entra PIM) are intentionally excluded -- see the
# two-approval model note above.
function Get-PimSummaryActionCategory {
    # Map an audit action string -> 'admin' | 'delegation' | 'removal' | $null
    # ($null = not a delegation/assignment lifecycle change -> dropped from the summary).
    param([Parameter(Mandatory)][string]$Action)
    $a = "$Action".Trim().ToLowerInvariant()
    if (-not $a) { return $null }
    # activation events are Entra-native -- never in the engine summary
    if ($a -match 'activat') { return $null }
    if ($a -match 'offboard|remove|revoke|delete') { return 'removal' }
    if ($a -match 'account\.create|admin\.create|account\.provision') { return 'admin' }
    if ($a -match 'assign|delegat|grant|approval.*approve') { return 'delegation' }
    return $null
}

function Get-PimDailySummary {
    # PURE: fold a set of audit events into a one-day summary of DELEGATION/ASSIGNMENT
    # lifecycle changes. Events are objects/hashtables with at least: ts (ISO), action,
    # target (+ optional actor, result). $SinceUtc/$NowUtc bound the window (default:
    # the 24h ending at NowUtc). Only result 'ok' (or unset) events count; whatIf
    # events are dropped. Returns @{ windowStartUtc; windowEndUtc; admins[]; delegations[];
    # removals[]; totalChanges; byActor{} }.
    param(
        [object[]]$Events = @(),
        [datetime]$NowUtc = [datetime]::UtcNow,
        [Nullable[datetime]]$SinceUtc
    )
    $end   = $NowUtc.ToUniversalTime()
    $start = if ($SinceUtc) { ([datetime]$SinceUtc).ToUniversalTime() } else { $end.AddDays(-1) }
    $admins = New-Object System.Collections.Generic.List[object]
    $dele   = New-Object System.Collections.Generic.List[object]
    $rem    = New-Object System.Collections.Generic.List[object]
    $byActor = @{}
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $res = (Get-PimNotifyField -Item $e -Name 'result')
        if ($res -and $res -ne 'ok') { continue }
        $wi = (Get-PimNotifyField -Item $e -Name 'whatIf')
        if ("$wi".Trim().ToLowerInvariant() -in @('true','1','yes')) { continue }
        $tsRaw = (Get-PimNotifyField -Item $e -Name 'ts'); if (-not "$tsRaw".Trim()) { $tsRaw = (Get-PimNotifyField -Item $e -Name 'enqueuedUtc') }
        $ts = [datetime]::MinValue
        if (-not [datetime]::TryParse("$tsRaw", [ref]$ts)) { continue }
        $ts = $ts.ToUniversalTime()
        if ($ts -lt $start -or $ts -gt $end) { continue }
        $cat = Get-PimSummaryActionCategory -Action (Get-PimNotifyField -Item $e -Name 'action')
        if (-not $cat) { continue }
        $rec = [pscustomobject]@{
            ts     = $ts.ToString('o')
            action = (Get-PimNotifyField -Item $e -Name 'action')
            target = (Get-PimNotifyField -Item $e -Name 'target')
            actor  = (Get-PimNotifyField -Item $e -Name 'actor')
        }
        switch ($cat) { 'admin' { $admins.Add($rec) } 'delegation' { $dele.Add($rec) } 'removal' { $rem.Add($rec) } }
        $ak = if ("$($rec.actor)".Trim()) { "$($rec.actor)" } else { 'engine' }
        if (-not $byActor.ContainsKey($ak)) { $byActor[$ak] = 0 }
        $byActor[$ak]++
    }
    [pscustomobject]@{
        windowStartUtc = $start.ToString('o')
        windowEndUtc   = $end.ToString('o')
        admins         = @($admins.ToArray() | Sort-Object ts)
        delegations    = @($dele.ToArray()   | Sort-Object ts)
        removals       = @($rem.ToArray()    | Sort-Object ts)
        totalChanges   = ($admins.Count + $dele.Count + $rem.Count)
        byActor        = $byActor
    }
}

function ConvertTo-PimDailySummaryHtmlList {
    # PURE helper: render a list of summary records to an HTML <ul> (or an "(none)"
    # line). Kept tiny so the template stays a flat token substitution.
    param([object[]]$Records = @())
    $r = @($Records)
    if ($r.Count -eq 0) { return '<p style="color:#57606a;">(none)</p>' }
    $items = foreach ($x in $r) {
        $when = "$($x.ts)"; try { $when = ([datetime]$x.ts).ToString('yyyy-MM-dd HH:mm') + ' UTC' } catch {}
        $actor = if ("$($x.actor)".Trim()) { " &mdash; by $(ConvertTo-PimHtmlEncoded "$($x.actor)")" } else { '' }
        '<li>' + (ConvertTo-PimHtmlEncoded "$($x.target)") + ' <span style="color:#57606a;">(' + (ConvertTo-PimHtmlEncoded "$($x.action)") + ", $when)$actor</span></li>"
    }
    '<ul style="margin:4px 0;">' + ($items -join '') + '</ul>'
}

function ConvertTo-PimDailySummaryTokens {
    # PURE: a Get-PimDailySummary result -> the token hashtable for the
    # daily-summary mail template.
    param([Parameter(Mandatory)][object]$Summary, [string]$TenantLabel = '')
    $wStart = "$($Summary.windowStartUtc)"; try { $wStart = ([datetime]$Summary.windowStartUtc).ToString('yyyy-MM-dd HH:mm') } catch {}
    $wEnd   = "$($Summary.windowEndUtc)";   try { $wEnd   = ([datetime]$Summary.windowEndUtc).ToString('yyyy-MM-dd HH:mm') } catch {}
    $label = if ("$TenantLabel".Trim()) { " - $TenantLabel" } else { '' }
    @{
        TenantLabel      = $label
        WindowStart      = "$wStart UTC"
        WindowEnd        = "$wEnd UTC"
        TotalChanges     = "$($Summary.totalChanges)"
        NewAdminCount    = "$(@($Summary.admins).Count)"
        DelegationCount  = "$(@($Summary.delegations).Count)"
        RemovalCount     = "$(@($Summary.removals).Count)"
        NewAdminList     = ConvertTo-PimDailySummaryHtmlList -Records $Summary.admins
        DelegationList   = ConvertTo-PimDailySummaryHtmlList -Records $Summary.delegations
        RemovalList      = ConvertTo-PimDailySummaryHtmlList -Records $Summary.removals
        Date             = (Get-Date).ToString('yyyy-MM-dd')
    }
}

# ---------------------------------------------------------------------------
# (2) TIER 0/1 REPORT -- every user with T0/T1 perms incl. level
# ---------------------------------------------------------------------------

function Get-PimRowTier {
    # Resolve a tier (int) from a row: explicit Tier/TierLevel field first, else the
    # name marker (T0/T1) used by the routing convention. $null when none found.
    param([Parameter(Mandatory)][object]$Row)
    foreach ($f in 'Tier','TierLevel','tier') {
        $v = (Get-PimNotifyField -Item $Row -Name $f)
        if ("$v".Trim() -match '^\s*[Tt]?\s*([0-9]+)\s*$') { return [int]$Matches[1] }
    }
    foreach ($f in 'UserName','GroupTag','GroupName','DisplayName','Name') {
        $v = (Get-PimNotifyField -Item $Row -Name $f)
        if ("$v" -match '(?i)(?:^|[-_])T([0-9])(?:[-_]|$)') { return [int]$Matches[1] }
    }
    return $null
}

function Get-PimRowLevel {
    # Resolve the privilege LEVEL (int) from a row: explicit Level field, else L# name marker.
    param([Parameter(Mandatory)][object]$Row)
    foreach ($f in 'Level','level') {
        $v = (Get-PimNotifyField -Item $Row -Name $f)
        if ("$v".Trim() -match '^\s*[Ll]?\s*([0-9]+)\s*$') { return [int]$Matches[1] }
    }
    foreach ($f in 'UserName','GroupTag','GroupName','DisplayName','Name') {
        $v = (Get-PimNotifyField -Item $Row -Name $f)
        if ("$v" -match '(?i)(?:^|[-_])L([0-9])(?:[-_]|$)') { return [int]$Matches[1] }
    }
    return $null
}

function Get-PimTierZeroOneReport {
    # PURE: from assignment rows (each with a user + a tag/group that carries a tier
    # marker), produce the set of users who hold Tier 0 or Tier 1 permissions, each with
    # the highest privilege (lowest tier number) they hold and the levels seen. Rows are
    # objects/hashtables with a user field (UserName/User/UserPrincipalName/Username) and a
    # tier/level (explicit field or name marker). Returns rows sorted T0 first, then user.
    param(
        [object[]]$Assignments = @(),
        [int[]]$Tiers = @(0,1)
    )
    $want = @{}; foreach ($t in @($Tiers)) { $want[[int]$t] = $true }
    $byUser = @{}
    foreach ($a in @($Assignments)) {
        if ($null -eq $a) { continue }
        $tier = Get-PimRowTier -Row $a
        if ($null -eq $tier -or -not $want.ContainsKey([int]$tier)) { continue }
        $user = ''
        foreach ($f in 'UserPrincipalName','UserName','Username','User','Upn') { $v = (Get-PimNotifyField -Item $a -Name $f); if ("$v".Trim()) { $user = "$v".Trim(); break } }
        if (-not $user) { continue }
        $level = Get-PimRowLevel -Row $a
        $tag = ''
        foreach ($f in 'GroupTag','GroupName','Group','Role','RoleName','Name') { $v = (Get-PimNotifyField -Item $a -Name $f); if ("$v".Trim()) { $tag = "$v".Trim(); break } }
        $uk = $user.ToLowerInvariant()
        if (-not $byUser.ContainsKey($uk)) {
            $byUser[$uk] = [pscustomobject]@{ user = $user; highestTier = [int]$tier; levels = (New-Object System.Collections.Generic.List[int]); grants = (New-Object System.Collections.Generic.List[object]); tierCounts = @{} }
        }
        $rec = $byUser[$uk]
        if ([int]$tier -lt [int]$rec.highestTier) { $rec.highestTier = [int]$tier }
        if ($null -ne $level -and -not $rec.levels.Contains([int]$level)) { $rec.levels.Add([int]$level) }
        if (-not $rec.tierCounts.ContainsKey([int]$tier)) { $rec.tierCounts[[int]$tier] = 0 }
        $rec.tierCounts[[int]$tier]++
        $rec.grants.Add([pscustomobject]@{ tier = [int]$tier; level = $level; tag = $tag })
    }
    $out = foreach ($k in $byUser.Keys) {
        $r = $byUser[$k]
        [pscustomobject]@{
            user        = $r.user
            highestTier = $r.highestTier
            levels      = @($r.levels.ToArray() | Sort-Object)
            grantCount  = $r.grants.Count
            grants      = @($r.grants.ToArray() | Sort-Object tier, level)
        }
    }
    @($out | Sort-Object highestTier, user)
}

function ConvertTo-PimTierReportHtmlRows {
    # PURE helper: tier-report rows -> HTML <tr> rows.
    param([object[]]$Report = @())
    $r = @($Report)
    if ($r.Count -eq 0) { return '<tr><td colspan="4" style="color:#57606a;">No Tier 0/1 holders found.</td></tr>' }
    $rows = foreach ($x in $r) {
        $lv = if (@($x.levels).Count) { (@($x.levels) -join ', ') } else { '&mdash;' }
        '<tr><td>' + (ConvertTo-PimHtmlEncoded "$($x.user)") + '</td><td>T' + [int]$x.highestTier + '</td><td>' + $lv + '</td><td>' + [int]$x.grantCount + '</td></tr>'
    }
    ($rows -join '')
}

function ConvertTo-PimTierReportTokens {
    # PURE: a Get-PimTierZeroOneReport result -> token hashtable for the tier-report mail.
    param([Parameter(Mandatory)][object[]]$Report, [string]$TenantLabel = '')
    $rep = @($Report)
    $label = if ("$TenantLabel".Trim()) { " - $TenantLabel" } else { '' }
    @{
        TenantLabel = $label
        T0Count     = "$(@($rep | Where-Object { [int]$_.highestTier -eq 0 }).Count)"
        T1Count     = "$(@($rep | Where-Object { [int]$_.highestTier -eq 1 }).Count)"
        TotalUsers  = "$($rep.Count)"
        ReportRows  = ConvertTo-PimTierReportHtmlRows -Report $rep
        Date        = (Get-Date).ToString('yyyy-MM-dd')
    }
}

# ---------------------------------------------------------------------------
# (3) ESCALATION / REMINDERS for DELEGATION approvals
#     serial  : owner[1] -> owner[2] after escalationHours (one at a time)
#     parallel: all owners at once, any-one decides (no serial step)
# ---------------------------------------------------------------------------
function Get-PimApprovalEscalationTargets {
    # PURE: who to notify NOW for a pending DELEGATION approval, given its mode + age.
    #   serial   -> the single current owner = owners[ floor(elapsedHours / escalationHours) ]
    #               (clamped to the last owner); isEscalated when step > 0.
    #   parallel -> ALL owners at once (any-one approves); never "escalates" to a different
    #               person, but re-fires as a REMINDER every escalationHours.
    # $Request carries requestedUtc (+ optional status, lastNotifiedStep, lastNotifiedUtc).
    # Returns @{ notify[]; mode; step; isEscalated; isReminder; elapsedHours; due } -- $null
    # when nothing is due (not pending / already notified this step within the interval).
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][string[]]$Owners,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [ValidateSet('serial','parallel')][string]$Mode = 'serial',
        [int]$EscalationHours = 24
    )
    $owners = @(@($Owners) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($owners.Count -eq 0) { return $null }
    $status = (Get-PimNotifyField -Item $Request -Name 'status')
    if ($status -and $status -ne 'pending') { return $null }
    $reqRaw = (Get-PimNotifyField -Item $Request -Name 'requestedUtc')
    $req = [datetime]::MinValue
    if (-not [datetime]::TryParse("$reqRaw", [ref]$req)) { return $null }
    $elapsed = ($NowUtc.ToUniversalTime() - $req.ToUniversalTime()).TotalHours
    if ($elapsed -lt 0) { $elapsed = 0 }
    $esc = if ($EscalationHours -gt 0) { $EscalationHours } else { 24 }

    if ($Mode -eq 'parallel') {
        # everyone at once; first send (step 0) immediately, then reminders each interval
        $step = [int][math]::Floor($elapsed / $esc)
        $lastStep = (Get-PimNotifyField -Item $Request -Name 'lastNotifiedStep')
        $last = if ("$lastStep".Trim() -match '^-?\d+$') { [int]$lastStep } else { -1 }
        if ($step -le $last) { return $null }   # already notified this interval
        return [pscustomobject]@{
            notify = @($owners); mode = 'parallel'; step = $step
            isEscalated = $false; isReminder = ($step -gt 0)
            elapsedHours = [int]$elapsed; totalOwners = $owners.Count; due = $true
        }
    }

    # serial: step through owners one at a time
    $step = [int][math]::Floor($elapsed / $esc)
    if ($step -ge $owners.Count) { $step = $owners.Count - 1 }
    $lastStep = (Get-PimNotifyField -Item $Request -Name 'lastNotifiedStep')
    $last = if ("$lastStep".Trim() -match '^-?\d+$') { [int]$lastStep } else { -1 }
    if ($step -le $last) { return $null }       # current owner already notified
    $prev = if ($step -gt 0) { $owners[$step - 1] } else { '' }
    return [pscustomobject]@{
        notify = @($owners[$step]); mode = 'serial'; step = $step
        previousApprover = $prev
        isEscalated = ($step -gt 0); isReminder = $false
        elapsedHours = [int]$elapsed; totalOwners = $owners.Count; due = $true
    }
}

function ConvertTo-PimEscalationTokens {
    # PURE: an escalation target + request facts -> tokens for approval-request /
    # approval-escalation templates (reuses the existing template token names).
    param(
        [Parameter(Mandatory)][object]$Target,
        [Parameter(Mandatory)][object]$Request,
        [string]$ApproverName = '',
        [string]$ApprovalUrl = ''
    )
    $appr = if ($ApproverName) { $ApproverName } else { "$(@($Target.notify)[0])" }
    @{
        ApproverName        = $appr
        PreviousApprover    = "$($Target.previousApprover)"
        RequestorUpn        = (Get-PimNotifyField -Item $Request -Name 'requestor')
        RoleName            = (Get-PimNotifyField -Item $Request -Name 'groupTag')
        GroupName           = (Get-PimNotifyField -Item $Request -Name 'groupTag')
        Justification       = (Get-PimNotifyField -Item $Request -Name 'justification')
        RequestedAt         = (Get-PimNotifyField -Item $Request -Name 'requestedUtc')
        EscalatedAfterHours = "$($Target.elapsedHours)"
        ApprovalUrl         = "$ApprovalUrl"
    }
}

# ---------------------------------------------------------------------------
# (4) ServiceNow -> Manager INTAKE (inbound only, store-and-forward, secure)
#     Threat model:
#       - No internet-facing webhook / Function. The Manager NEVER calls out.
#       - The external workflow drops a signed request file into a one-way store
#         (a drop dir / SQL table); the Manager POLLS it when up (store-and-forward,
#         works even when the Manager was down).
#       - An intake request can NEVER self-create or self-activate. Privileged types
#         always route to APPROVE (a human gate); only an explicit, configured
#         allowlist of low-risk types may auto-apply -- and even then never activation.
# ---------------------------------------------------------------------------

# Field allowlist: only these are read off an inbound payload; anything else is dropped
# (so a crafted payload can't smuggle extra instructions through).
$script:PimIntakeAllowedFields = @('externalId','requestType','requestor','targetAdmin','groupTag','justification','tier','level','requestedUtc','source')

function ConvertTo-PimIntakeRecord {
    # PURE: normalise + sanitise a raw inbound payload into a safe intake record.
    # Drops unknown fields, trims, forces status='received', stamps receivedUtc, and
    # carries NO executable capability -- it is data only. Returns $null when the
    # mandatory fields (requestType + requestor) are missing.
    param([Parameter(Mandatory)][object]$Payload, [datetime]$NowUtc = [datetime]::UtcNow)
    $rec = [ordered]@{}
    foreach ($f in $script:PimIntakeAllowedFields) {
        $v = (Get-PimNotifyField -Item $Payload -Name $f)
        if ("$v".Trim()) { $rec[$f] = "$v".Trim() }
    }
    if (-not "$($rec['requestType'])".Trim() -or -not "$($rec['requestor'])".Trim()) { return $null }
    $rec['id']          = [guid]::NewGuid().ToString()
    $rec['status']      = 'received'
    $rec['receivedUtc'] = $NowUtc.ToUniversalTime().ToString('o')
    return [pscustomobject]$rec
}

# Request types that MAY auto-apply (low risk, never privileged, never activation).
# Everything else -- and anything Tier 0/1 -- routes to APPROVE. Override via config
# key 'IntakeAutoApplyTypes'. Activation is NEVER auto-applied or even accepted as a type.
function Get-PimIntakeAutoApplyTypes {
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $c = Get-PimPolicySetting -Name 'IntakeAutoApplyTypes' -Default $null
        if ($null -ne $c) { return @($c) }
    }
    if ($global:PIM_IntakeAutoApplyTypes) { return @($global:PIM_IntakeAutoApplyTypes) }
    return @()   # secure default: nothing auto-applies; everything needs a human approve
}

function Test-PimIntakeAccepted {
    # PURE security gate: is this intake record acceptable AT ALL? Rejects activation
    # requests (Entra-native, never via intake), self-targeting requests (requestor ==
    # targetAdmin -> no self-elevation), and records missing the mandatory shape.
    # Returns @{ accepted; reason }.
    param([Parameter(Mandatory)][object]$Record)
    $type = (Get-PimNotifyField -Item $Record -Name 'requestType').ToLowerInvariant()
    if (-not $type) { return [pscustomobject]@{ accepted = $false; reason = 'missing requestType' } }
    if ($type -match 'activat') { return [pscustomobject]@{ accepted = $false; reason = 'activation is Entra-native -- never accepted via intake' } }
    $requestor = (Get-PimNotifyField -Item $Record -Name 'requestor').Trim().ToLowerInvariant()
    $target    = (Get-PimNotifyField -Item $Record -Name 'targetAdmin').Trim().ToLowerInvariant()
    if (-not $requestor) { return [pscustomobject]@{ accepted = $false; reason = 'missing requestor' } }
    if ($target -and $target -eq $requestor) { return [pscustomobject]@{ accepted = $false; reason = 'self-targeting request rejected (no self-create/self-elevate)' } }
    return [pscustomobject]@{ accepted = $true; reason = 'ok' }
}

function Resolve-PimIntakeRouting {
    # PURE: where does an ACCEPTED intake record go? -> 'reject' | 'approve' | 'auto-apply'.
    # Hard rule: Tier 0/1 (explicit field OR group-tag marker) ALWAYS routes to 'approve';
    # only an allowlisted, non-privileged type auto-applies. Never 'auto-apply' for
    # activation (already blocked upstream) or privileged tiers.
    param([Parameter(Mandatory)][object]$Record, [string[]]$AutoApplyTypes)
    $gate = Test-PimIntakeAccepted -Record $Record
    if (-not $gate.accepted) { return [pscustomobject]@{ route = 'reject'; reason = $gate.reason } }
    $type = (Get-PimNotifyField -Item $Record -Name 'requestType').ToLowerInvariant()
    $tier = Get-PimRowTier -Row $Record
    if ($null -ne $tier -and [int]$tier -le 1) {
        return [pscustomobject]@{ route = 'approve'; reason = "Tier $tier -- human approval required" }
    }
    if (-not $AutoApplyTypes) { $AutoApplyTypes = Get-PimIntakeAutoApplyTypes }
    $allow = @(@($AutoApplyTypes) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ($allow -contains $type) { return [pscustomobject]@{ route = 'auto-apply'; reason = "type '$type' is allowlisted + non-privileged" } }
    return [pscustomobject]@{ route = 'approve'; reason = "type '$type' not allowlisted -- human approval required" }
}

# ---- store-and-forward broker (file/SQL adapter; JSONL drop store now) ----------
function Read-PimIntakeStore {
    # Read pending intake records the external workflow has dropped (append-only JSONL,
    # one record/line). Returns @() when the store does not exist. Storage-agnostic: the
    # SQL adapter lands with the data layer; this file form proves the polling model.
    param([Parameter(Mandatory)][string]$StoreFile)
    if (-not (Test-Path -LiteralPath $StoreFile)) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($line in (Get-Content -LiteralPath $StoreFile -Encoding UTF8)) {
        if (-not "$line".Trim()) { continue }
        try { $out.Add(("$line" | ConvertFrom-Json)) } catch {}
    }
    return $out.ToArray()
}

function Add-PimIntakeRecord {
    # Append a sanitised intake record to the drop store (what the EXTERNAL side would do;
    # also used by the Manager to mark a record processed by re-writing the store).
    param([Parameter(Mandatory)][string]$StoreFile, [Parameter(Mandatory)][object]$Record)
    $dir = Split-Path -Parent $StoreFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::AppendAllText($StoreFile, (($Record | ConvertTo-Json -Depth 8 -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
}

function Invoke-PimIntakePoll {
    # PURE-ish orchestration (no network, no apply): read the store, sanitise + route
    # every pending record, and return the routing decisions. The CALLER turns an
    # 'approve' into a New-PimApprovalRequest / approval mail and an 'auto-apply' into a
    # change-queue entry -- this function never mutates anything itself, so it is safe to
    # poll repeatedly and fully testable. Records already carrying a non-'received' status
    # are skipped (idempotent).
    param([Parameter(Mandatory)][string]$StoreFile, [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$AutoApplyTypes)
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @(Read-PimIntakeStore -StoreFile $StoreFile)) {
        $st = (Get-PimNotifyField -Item $raw -Name 'status')
        if ($st -and $st -ne 'received') { continue }
        # re-sanitise on the way in even if the producer already shaped it
        $rec = ConvertTo-PimIntakeRecord -Payload $raw -NowUtc $NowUtc
        if (-not $rec) { $results.Add([pscustomobject]@{ route = 'reject'; reason = 'malformed record'; record = $raw }); continue }
        $route = Resolve-PimIntakeRouting -Record $rec -AutoApplyTypes $AutoApplyTypes
        $results.Add([pscustomobject]@{ route = $route.route; reason = $route.reason; record = $rec })
    }
    return $results.ToArray()
}
