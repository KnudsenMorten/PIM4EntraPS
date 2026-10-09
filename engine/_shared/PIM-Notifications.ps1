# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
# MAIL-2: the designed layout + notification preferences the daily-changes report is built with (same defensive load).
if (-not (Get-Command New-PimMailDocument -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-MailLayout.ps1') }
if (-not (Get-Command Get-PimAudienceLink -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-MailNotifications.ps1') }
if (-not (Get-Command Invoke-PimGetStartedReminder -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-GetStartedReminder.ps1') }
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

function Expand-PimSummaryCommitEvent {
    # PURE. One audit event -> the event(s) the summary categorises. Only a 'config.csv.save' on an
    # admin or assignment entity is expanded (adds -> new admin / delegation, modifies -> delegation,
    # removes -> removal); every other event passes through unchanged.
    param([Parameter(Mandatory)][object]$AuditEvent)
    $action = Get-PimNotifyField -Item $AuditEvent -Name 'action'
    $target = Get-PimNotifyField -Item $AuditEvent -Name 'target'
    # §70.14: the action is 'config.save' from v2.4.348; 'config.csv.save' is how older commits were recorded.
    if ("$action" -notin @('config.save', 'config.csv.save') -or "$target" -notmatch '^(Account-Definitions-Admins|PIM-Assignments-.+)$') { return @($AuditEvent) }
    $after = $null
    if ($AuditEvent -is [System.Collections.IDictionary]) { if ($AuditEvent.Contains('after')) { $after = $AuditEvent['after'] } }
    else { $p = $AuditEvent.PSObject.Properties['after']; if ($p) { $after = $p.Value } }
    if ($after -is [string]) { try { $after = $after | ConvertFrom-Json } catch { $after = $null } }
    $num = { param($n) $v = 0; if ($null -ne $after) { [void][int]::TryParse("$(Get-PimNotifyField -Item $after -Name $n)", [ref]$v) }; $v }
    $adds = & $num 'adds'; $removes = & $num 'removes'; $mods = & $num 'modifies'
    $base = @{ ts = (Get-PimNotifyField -Item $AuditEvent -Name 'ts'); actor = (Get-PimNotifyField -Item $AuditEvent -Name 'actor'); result = (Get-PimNotifyField -Item $AuditEvent -Name 'result'); whatIf = (Get-PimNotifyField -Item $AuditEvent -Name 'whatIf') }
    $out = New-Object System.Collections.ArrayList
    $isAdmin = ("$target" -eq 'Account-Definitions-Admins')
    if ($adds -gt 0) {
        $o = @{} + $base; $o['action'] = $(if ($isAdmin) { 'account.create' } else { 'assign.commit' }); $o['target'] = ("{0} (+{1} row(s))" -f $target, $adds); [void]$out.Add([pscustomobject]$o)
    }
    if ($mods -gt 0 -and -not $isAdmin) {
        $o = @{} + $base; $o['action'] = 'assign.commit.update'; $o['target'] = ("{0} ({1} row(s) changed)" -f $target, $mods); [void]$out.Add([pscustomobject]$o)
    }
    if ($removes -gt 0) {
        $o = @{} + $base; $o['action'] = 'remove.commit'; $o['target'] = ("{0} (-{1} row(s))" -f $target, $removes); [void]$out.Add([pscustomobject]$o)
    }
    return $out.ToArray()
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
    # A Manager COMMIT is audited as ONE 'config.csv.save' per entity (adds/removes/modifies), whose
    # action name matches no category -- so a digest over the SQL audit trail would miss every
    # delegation an operator committed. Expand those into per-category events first.
    $expanded = New-Object System.Collections.ArrayList
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        foreach ($x in @(Expand-PimSummaryCommitEvent -AuditEvent $e)) { [void]$expanded.Add($x) }
    }
    foreach ($e in $expanded.ToArray()) {
        if ($null -eq $e) { continue }
        $res = (Get-PimNotifyField -Item $e -Name 'result')
        if ($res -and $res -ne 'ok') { continue }
        $wi = (Get-PimNotifyField -Item $e -Name 'whatIf')
        if ("$wi".Trim().ToLowerInvariant() -in @('true','1','yes')) { continue }
        $tsRaw = (Get-PimNotifyField -Item $e -Name 'ts'); if (-not "$tsRaw".Trim()) { $tsRaw = (Get-PimNotifyField -Item $e -Name 'enqueuedUtc') }
        $ts = Get-PimUtcStamp $tsRaw   # IMP-02
        if ($null -eq $ts) { continue }
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
    $adm = ConvertTo-PimDailySummaryHtmlList -Records $Summary.admins
    $del = ConvertTo-PimDailySummaryHtmlList -Records $Summary.delegations
    $rem = ConvertTo-PimDailySummaryHtmlList -Records $Summary.removals
    @{
        # MAIL-2: the designed template's tokens. ConvertTo-PimDailyChangesTokens replaces ReportHtml with the full report;
        # a caller with only the summary still gets a readable body (the three lists), never an empty mail.
        ReportHtml       = ('<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#24292f;padding:16px;"><h3>New privileged admins</h3>' + $adm + '<h3>New delegations / assignments</h3>' + $del + '<h3>Removals / offboardings</h3>' + $rem + '</div>')
        RiskyCount       = '0'
        RiskyNote        = ''
        ActorCount       = "$(@($Summary.byActor.Keys).Count)"
        TenantLabel      = $label
        WindowStart      = "$wStart UTC"
        WindowEnd        = "$wEnd UTC"
        TotalChanges     = "$($Summary.totalChanges)"
        NewAdminCount    = "$(@($Summary.admins).Count)"
        DelegationCount  = "$(@($Summary.delegations).Count)"
        RemovalCount     = "$(@($Summary.removals).Count)"
        NewAdminList     = $adm
        DelegationList   = $del
        RemovalList      = $rem
        Date             = (Get-Date).ToString('yyyy-MM-dd')
    }
}

# ---------------------------------------------------------------------------
# (1b) DAILY CHANGES -- the redesigned daily mail (framework §12.11 MAIL-2, PIM §100.5; owner via Invardia 2026-10-09:
# "fx daily changes must be improved in pim"). Summary first (how many, by whom, what kind, anything risky), grouped
# tables with before -> after, the audience button, the logo. PURE: events in, report object / HTML out.
# ---------------------------------------------------------------------------

# The Entra / Azure / AD roles a grant of which is called out as RISKY (tier-0 control-plane roles).
$script:PimRiskyRoleNames = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator', 'Security Administrator',
    'Conditional Access Administrator', 'Application Administrator', 'Cloud Application Administrator', 'Hybrid Identity Administrator',
    'Authentication Policy Administrator', 'Partner Tier2 Support', 'Intune Administrator', 'Exchange Administrator',
    'User Access Administrator', 'Domain Admins', 'Enterprise Admins', 'Schema Admins'
)

function Get-PimChangeAreaLabel {
    # PURE. The entity a commit wrote -> what a reader calls it.
    param([string]$Target)
    $t = "$Target" -replace '\s*\(.*$', ''
    switch -Regex ($t) {
        '^PIM-Assignments-Admins$'          { return 'Admin to group' }
        '^PIM-Assignments-Groups$'          { return 'Group nesting' }
        '^PIM-Assignments-Roles-Groups$'    { return 'Entra role' }
        '^PIM-Assignments-Roles-AUs$'       { return 'Entra role in an administrative unit' }
        '^PIM-Assignments-Azure-Resources$' { return 'Azure role' }
        '^PIM-Assignments-Workloads$'       { return 'Workload role' }
        '^PIM-Assignments-'                 { return 'Delegation' }
        '^Account-Definitions-Admins$'      { return 'Admin account' }
        '^settings:breakglass'              { return 'Break-glass accounts' }
        default                             { return $(if ($t) { $t } else { 'Other' }) }
    }
}

function Get-PimChangeRiskReason {
    <#
      PURE. Why ONE change needs a look ('' = it does not). Risky, defined from the data (MAIL-2 / §100.5):
        * a safety guard released (guard.release*, the second-person guard release setting)
        * a break-glass account change (settings.breakglass-accounts.*, or the text names break-glass)
        * an emergency override (emergency.*)
        * a removal / offboarding / revoke
        * a grant of a tier-0 role (Global Administrator, Privileged Role Administrator, ... Owner on Azure) or of Tier 0 access
    #>
    param([string]$Kind = '', [string]$Action = '', [string]$Text = '')
    $a = "$Action".Trim().ToLowerInvariant(); $t = "$Text"
    if ($a -match 'guard\.release|guard-release') { return 'a safety guard was released' }
    if ($a -match 'break-?glass' -or $t -match '(?i)break-?glass') { return 'break-glass account change' }
    if ($a -match '^emergency\.') { return 'emergency override' }
    if ($Kind -eq 'Removed' -or $a -match 'offboard|remove|revoke|delete') { return 'access removed' }
    foreach ($n in $script:PimRiskyRoleNames) { if ($t.IndexOf($n, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return "privileged role: $n" } }
    if ($t -match "(?i)Azure role '(Owner|User Access Administrator)'") { return "privileged Azure role: $($Matches[1])" }
    if ($t -match '(?i)(^|[^A-Za-z0-9])T0([^A-Za-z0-9]|$)') { return 'Tier 0 access' }
    return ''
}

function ConvertFrom-PimCommitChangeLine {
    # PURE. One readable commit sentence ("Added: ...", "Removed: ...", "Changed: X -- Col: a -> b; Col2: c -> d") ->
    # @{ kind; what; before; after }.
    param([string]$Line)
    $l = "$Line".Trim()
    $kind = 'Changed'; $rest = $l
    if ($l -match '^(Added|Removed|Changed):\s*(.*)$') { $kind = $Matches[1]; $rest = $Matches[2] }
    $before = ''; $after = ''; $what = $rest
    if ($kind -eq 'Changed' -and $rest -match '^(.*?)\s+--\s+(.+)$') {
        $what = $Matches[1]
        $b = New-Object System.Collections.Generic.List[string]; $a = New-Object System.Collections.Generic.List[string]
        foreach ($part in ($Matches[2] -split ';\s*')) {
            if ($part -match '^\s*([^:]+):\s*(.*?)\s+->\s+(.*)$') { $b.Add("$($Matches[1].Trim()): $($Matches[2].Trim())"); $a.Add("$($Matches[1].Trim()): $($Matches[3].Trim())") }
        }
        $before = ($b.ToArray() -join '; '); $after = ($a.ToArray() -join '; ')
    } elseif ($kind -eq 'Added') { $before = '(none)'; $after = 'added' }
    elseif ($kind -eq 'Removed') { $before = 'present'; $after = '(removed)' }
    return [pscustomobject]@{ kind = $kind; what = $what; before = $before; after = $after }
}

function Get-PimDailyChangesReport {
    <#
      PURE. Fold audit events into the DAILY CHANGES report. Same window, the same ok / not-whatIf / no-activation rules and
      the same Manager-commit expansion as Get-PimDailySummary; in addition:
        * a commit that recorded its row sentences (after.changes, v2.4.348+) becomes ONE row per changed row, with
          before -> after for a change;
        * safety events are rows too, even though they are not delegations: guard releases, break-glass account changes,
          emergency overrides;
        * every row is judged RISKY or not (Get-PimChangeRiskReason).
      Returns @{ windowStartUtc; windowEndUtc; total; rows[]; risky[]; byKind{}; byActor[] (actor, changes, risky);
                 actorCount; removals; summary (the Get-PimDailySummary result, for the old tokens) }.
    #>
    param([object[]]$Events = @(), [datetime]$NowUtc = [datetime]::UtcNow, [Nullable[datetime]]$SinceUtc)
    $end = $NowUtc.ToUniversalTime()
    $start = if ($SinceUtc) { ([datetime]$SinceUtc).ToUniversalTime() } else { $end.AddDays(-1) }
    $rows = New-Object System.Collections.Generic.List[object]
    $add = {
        param($ts, $actor, $kind, $area, $what, $before, $after, $action, $target)
        $why = Get-PimChangeRiskReason -Kind $kind -Action $action -Text ("$what $before $after $target")
        $rows.Add([pscustomobject]@{
            ts = $ts.ToString('o'); when = $ts.ToString('yyyy-MM-dd HH:mm') + ' UTC'
            actor = $(if ("$actor".Trim()) { "$actor".Trim() } else { 'engine' })
            kind = $kind; area = $area; what = "$what"; before = "$before"; after = "$after"
            risky = [bool]$why; riskReason = $why; action = "$action"; target = "$target"
        })
    }
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $res = Get-PimNotifyField -Item $e -Name 'result'
        if ($res -and $res -ne 'ok') { continue }
        if ("$(Get-PimNotifyField -Item $e -Name 'whatIf')".Trim().ToLowerInvariant() -in @('true', '1', 'yes')) { continue }
        $tsRaw = Get-PimNotifyField -Item $e -Name 'ts'; if (-not "$tsRaw".Trim()) { $tsRaw = Get-PimNotifyField -Item $e -Name 'enqueuedUtc' }
        $ts = Get-PimUtcStamp $tsRaw
        if ($null -eq $ts -or $ts -lt $start -or $ts -gt $end) { continue }
        $action = Get-PimNotifyField -Item $e -Name 'action'; $target = Get-PimNotifyField -Item $e -Name 'target'; $actor = Get-PimNotifyField -Item $e -Name 'actor'
        $al = "$action".Trim().ToLowerInvariant()
        if ($al -match 'activat') { continue }   # Entra-native, never in this report (two-approval model)
        # A commit with its row sentences: one row per changed row.
        if ($al -in @('config.save', 'config.csv.save') -and "$target" -match '^(Account-Definitions-Admins|PIM-Assignments-.+)$') {
            $after = $null
            if ($e -is [System.Collections.IDictionary]) { if ($e.Contains('after')) { $after = $e['after'] } } else { $p = $e.PSObject.Properties['after']; if ($p) { $after = $p.Value } }
            if ($after -is [string]) { try { $after = $after | ConvertFrom-Json } catch { $after = $null } }
            $lines = @()
            if ($null -ne $after) {
                $ch = if ($after -is [System.Collections.IDictionary]) { if ($after.Contains('changes')) { $after['changes'] } } else { $pp = $after.PSObject.Properties['changes']; if ($pp) { $pp.Value } }
                $lines = @(@($ch) | Where-Object { "$_".Trim() -and "$_" -notmatch '^\(the row details' })
            }
            if ($lines.Count) {
                foreach ($ln in $lines) { $c = ConvertFrom-PimCommitChangeLine -Line "$ln"; & $add $ts $actor $c.kind (Get-PimChangeAreaLabel -Target $target) $c.what $c.before $c.after $action $target }
                continue
            }
            # An older commit (counts only): the summary's own expansion, one row per kind.
            foreach ($x in @(Expand-PimSummaryCommitEvent -AuditEvent $e)) {
                $cat = Get-PimSummaryActionCategory -Action "$($x.action)"
                if (-not $cat) { continue }
                $k = switch ($cat) { 'admin' { 'Added' } 'removal' { 'Removed' } default { if ("$($x.action)" -match 'update') { 'Changed' } else { 'Added' } } }
                & $add $ts $actor $k (Get-PimChangeAreaLabel -Target $target) "$($x.target)" '' '' "$($x.action)" $target
            }
            continue
        }
        # Safety events -- rows even though they are not delegations.
        if ($al -match '^guard\.release|^settings\.guard-release') { & $add $ts $actor 'Guard release' 'Safety guard' "$target" '' '' $action $target; continue }
        if ($al -match '^settings\.breakglass-accounts\.') { & $add $ts $actor 'Break-glass' 'Break-glass accounts' ("$target ($($al -replace '^settings\.breakglass-accounts\.', ''))") '' '' $action $target; continue }
        if ($al -match '^emergency\.') { & $add $ts $actor 'Emergency' 'Emergency override' ("$target ($al)") '' '' $action $target; continue }
        # Every other delegation / account lifecycle event the summary counts.
        $cat = Get-PimSummaryActionCategory -Action "$action"
        if (-not $cat) { continue }
        $k = switch ($cat) { 'admin' { 'Added' } 'removal' { 'Removed' } default { 'Added' } }
        $area = if ($cat -eq 'admin') { 'Admin account' } else { Get-PimChangeAreaLabel -Target $target }
        & $add $ts $actor $k $area "$target" '' '' $action $target
    }
    $all = @($rows.ToArray() | Sort-Object ts)
    $byKind = [ordered]@{}
    foreach ($k in 'Added', 'Changed', 'Removed', 'Guard release', 'Break-glass', 'Emergency') { $n = @($all | Where-Object { $_.kind -eq $k }).Count; if ($n) { $byKind[$k] = $n } }
    $byActor = @($all | Group-Object actor | ForEach-Object { [pscustomobject]@{ actor = $_.Name; changes = $_.Count; risky = @($_.Group | Where-Object { $_.risky }).Count } } | Sort-Object @{ Expression = 'changes'; Descending = $true }, actor)
    [pscustomobject]@{
        windowStartUtc = $start.ToString('o'); windowEndUtc = $end.ToString('o')
        total = $all.Count; rows = $all; risky = @($all | Where-Object { $_.risky })
        byKind = $byKind; byActor = $byActor; actorCount = @($byActor).Count
        removals = @($all | Where-Object { $_.kind -eq 'Removed' }).Count
        summary = (Get-PimDailySummary -Events $Events -NowUtc $NowUtc -SinceUtc $start)
    }
}

function ConvertTo-PimDailyChangesHtml {
    <#
      PURE. The daily-changes report as designed HTML (MAIL-2 items 1, 4, 7): summary first, the risky changes in a red box,
      the audience button, then by kind / by person / every change grouped by kind with before -> after.
        -Audience   soc | posture | manager (picks the button) ; -PortalBase  the Manager address ('' = no links)
        -Environment @{ name; tenantName; tenantId; version } ; -Print  the print-ready document (no row cap) for the PDF copy
    #>
    param([Parameter(Mandatory)][object]$Report, [ValidateSet('soc', 'posture', 'manager')][string]$Audience = 'manager', [string]$PortalBase = '',
          [hashtable]$Environment = @{}, [switch]$Print, [int]$MaxRowsPerKind = 40)
    $enc = { param($v) ConvertTo-PimMailText $v }
    $ws = [datetime]::Parse("$($Report.windowStartUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    $we = [datetime]::Parse("$($Report.windowEndUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    $dayQ = 'from=' + $ws.ToString('yyyy-MM-dd') + '&to=' + $we.ToString('yyyy-MM-dd')
    $btn = Get-PimAudienceLink -Type 'daily-summary' -Audience $Audience -Base $PortalBase -Query $dayQ
    $auditAll = (Get-PimAudienceLink -Type 'daily-summary' -Audience 'soc' -Base $PortalBase -Query $dayQ).url
    $homeUrl = if ("$PortalBase".Trim()) { (Get-PimAudienceLink -Type 'home' -Base $PortalBase -LinkTab 'home').url -replace '/\?tab=home$', '/' } else { '' }
    $notif = (Get-PimAudienceLink -Type 'settings' -Base $PortalBase -LinkTab 'settings' -Query 'section=notifications').url
    $total = [int]$Report.total; $risky = @($Report.risky); $actors = [int]$Report.actorCount
    $kinds = $Report.byKind
    $kindTxt = (@($kinds.Keys | ForEach-Object { '{0} {1}' -f $kinds[$_], "$_".ToLowerInvariant() }) -join ', ')
    $headline = if ($total -eq 0) { 'No delegation, admin account or safety changes in this window.' }
                else { ('{0} change(s) by {1} {2}: {3}. {4}' -f $total, $actors, $(if ($actors -eq 1) { 'person' } else { 'people' }), $kindTxt,
                        $(if ($risky.Count) { "$($risky.Count) need(s) a look." } else { 'Nothing risky.' })) }
    $tiles = New-PimMailSummaryTiles -Tiles @(
        @{ label = 'Changes'; value = "$total"; tone = 'accent' }
        @{ label = 'Need a look'; value = "$($risky.Count)"; tone = $(if ($risky.Count) { 'danger' } else { 'good' }); hint = $(if ($risky.Count) { 'removals, tier-0 roles, guards, break-glass' } else { 'nothing risky' }) }
        @{ label = 'People'; value = "$actors"; tone = 'neutral' }
        @{ label = 'Removed'; value = "$([int]$Report.removals)"; tone = $(if ([int]$Report.removals) { 'warning' } else { 'neutral' }) }
    )
    $summary = $tiles + '<p style="font-family:' + (Get-PimMailBrand).font + ';font-size:14px;margin:10px 0 0 0;">' + (& $enc $headline) + '</p>'
    if ($risky.Count) {
        $rt = New-PimMailTable -Columns @(@{ key = 'when'; label = 'When' }, @{ key = 'actor'; label = 'Who' }, @{ key = 'what'; label = 'What' }, @{ key = 'riskReason'; label = 'Why it needs a look' }) `
                               -Rows $risky -MaxRows $(if ($Print) { 0 } else { 15 }) -MoreUrl $auditAll -MoreLabel 'See them in the audit trail'
        $summary += New-PimMailCallout -Tone 'danger' -Title ("Needs a look ({0})" -f $risky.Count) -Html $rt
    }
    $body = ''
    if ($total -gt 0) {
        $kt = New-PimMailTable -Columns @(@{ key = 'kind'; label = 'Kind' }, @{ key = 'n'; label = 'Changes' }) -Rows @($kinds.Keys | ForEach-Object { [pscustomobject]@{ kind = $_; n = $kinds[$_] } })
        $pt = New-PimMailTable -Columns @(@{ key = 'actor'; label = 'Person' }, @{ key = 'changes'; label = 'Changes' }, @{ key = 'risky'; label = 'Need a look' }) -Rows @($Report.byActor)
        $body += '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0"><tr><td valign="top" style="width:48%;padding-right:2%;">' + (New-PimMailSection -Title 'By kind' -Html $kt) +
                 '</td><td valign="top" style="width:50%;">' + (New-PimMailSection -Title 'By person' -Html $pt) + '</td></tr></table>'
        foreach ($k in @($kinds.Keys)) {
            $kr = @($Report.rows | Where-Object { $_.kind -eq $k })
            $rowsHtml = @($kr | ForEach-Object {
                $w = (& $enc $_.what); if ($_.risky) { $w = '<span style="color:#cf222e;font-weight:600;">&#9888;</span> ' + $w }
                [pscustomobject]@{ when = $_.when; actor = $_.actor; area = $_.area; what = $w; before = $_.before; after = $_.after }
            })
            $cols = @(@{ key = 'when'; label = 'When'; width = '96px' }, @{ key = 'actor'; label = 'Who' }, @{ key = 'area'; label = 'Area' }, @{ key = 'what'; label = 'What'; html = $true })
            if (@($kr | Where-Object { "$($_.before)$($_.after)".Trim() -and $_.kind -eq 'Changed' }).Count) { $cols += @(@{ key = 'before'; label = 'Before' }, @{ key = 'after'; label = 'After' }) }
            $body += New-PimMailSection -Title ("{0} ({1})" -f $k, $kr.Count) -Html (New-PimMailTable -Columns $cols -Rows $rowsHtml -MaxRows $(if ($Print) { 0 } else { $MaxRowsPerKind }) -MoreUrl $auditAll -MoreLabel 'See all of them in the audit trail')
        }
        $body += '<p style="font-family:' + (Get-PimMailBrand).font + ';font-size:12px;color:#57606a;margin:14px 0 0 0;">Activation of eligible roles is handled and notified natively by Entra PIM and is not listed here. Every change above is recorded in the audit trail.</p>'
    }
    $sub = ('{0} UTC to {1} UTC' -f $ws.ToString('yyyy-MM-dd HH:mm'), $we.ToString('yyyy-MM-dd HH:mm'))
    $pre = $headline
    return (New-PimMailDocument -Title 'Daily changes' -Subtitle $sub -Preheader $pre -SummaryHtml $summary -BodyHtml $body `
                -Button $(if ($btn.url) { @{ url = $btn.url; label = $btn.label } } else { $null }) -HomeUrl $homeUrl -NotificationsUrl $notif `
                -Environment $Environment -AudienceLabel (Get-PimMailAudienceLabel $Audience) -GeneratedUtc $we -Print:$Print)
}

function ConvertTo-PimDailyChangesTokens {
    <#
      The daily-summary template tokens for ONE audience: every token the old template used (ConvertTo-PimDailySummaryTokens,
      so a customer-EDITED template keeps rendering) plus ReportHtml (the designed body), RiskyCount, ActorCount and the
      subject's TotalChanges from the report.
    #>
    param([Parameter(Mandatory)][object]$Report, [string]$TenantLabel = '', [ValidateSet('soc', 'posture', 'manager')][string]$Audience = 'manager', [string]$PortalBase = '', [hashtable]$Environment = @{})
    $t = ConvertTo-PimDailySummaryTokens -Summary $Report.summary -TenantLabel $TenantLabel
    $t['TotalChanges'] = "$([int]$Report.total)"
    $t['RiskyCount'] = "$(@($Report.risky).Count)"
    $t['ActorCount'] = "$([int]$Report.actorCount)"
    $t['RiskyNote'] = $(if (@($Report.risky).Count) { ", $(@($Report.risky).Count) need a look" } else { '' })
    $t['ReportHtml'] = ConvertTo-PimDailyChangesHtml -Report $Report -Audience $Audience -PortalBase $PortalBase -Environment $Environment
    $t['PortalQuery'] = ''
    return $t
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
        # MAIL-2: the designed body; ConvertTo-PimTierReportDesignedTokens replaces it per audience. A summary-only fallback here.
        ReportHtml  = ('<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#24292f;padding:16px;"><table cellpadding="6" style="border-collapse:collapse;border:1px solid #d0d7de;"><tr><th align="left">User</th><th align="left">Highest tier</th><th align="left">Level(s)</th><th align="left">Grants</th></tr>' + (ConvertTo-PimTierReportHtmlRows -Report $rep) + '</table></div>')
        TenantLabel = $label
        T0Count     = "$(@($rep | Where-Object { [int]$_.highestTier -eq 0 }).Count)"
        T1Count     = "$(@($rep | Where-Object { [int]$_.highestTier -eq 1 }).Count)"
        TotalUsers  = "$($rep.Count)"
        ReportRows  = ConvertTo-PimTierReportHtmlRows -Report $rep
        Date        = (Get-Date).ToString('yyyy-MM-dd')
    }
}

function ConvertTo-PimTierReportDesignedTokens {
    <#
      MAIL-2 items 1, 4, 7: the tier report in the designed layout, for ONE audience -- tiles (Tier 0 / Tier 1 holders, people),
      the blue button (SOC: investigate in reports; posture: the delegation map; manager: access reviews), the table with the
      Tier 0 holders first. Every old token stays (an edited template keeps rendering).
    #>
    param([Parameter(Mandatory)][object[]]$Report, [string]$TenantLabel = '', [ValidateSet('soc', 'posture', 'manager')][string]$Audience = 'manager',
          [string]$PortalBase = '', [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Print)
    $t = ConvertTo-PimTierReportTokens -Report $Report -TenantLabel $TenantLabel
    $rep = @($Report)
    $t0 = @($rep | Where-Object { [int]$_.highestTier -eq 0 }); $t1 = @($rep | Where-Object { [int]$_.highestTier -eq 1 })
    $btn = Get-PimAudienceLink -Type 'tier-report' -Audience $Audience -Base $PortalBase
    $homeUrl = if ("$PortalBase".Trim()) { (Get-PimAudienceLink -Type 'home' -Base $PortalBase -LinkTab 'home').url -replace '/\?tab=home$', '/' } else { '' }
    $notif = (Get-PimAudienceLink -Type 'settings' -Base $PortalBase -LinkTab 'settings' -Query 'section=notifications').url
    $tiles = New-PimMailSummaryTiles -Tiles @(
        @{ label = 'Tier 0 holders'; value = "$($t0.Count)"; tone = $(if ($t0.Count) { 'danger' } else { 'good' }) }
        @{ label = 'Tier 1 holders'; value = "$($t1.Count)"; tone = $(if ($t1.Count) { 'warning' } else { 'good' }) }
        @{ label = 'People'; value = "$($rep.Count)"; tone = 'accent' })
    $sum = $tiles + '<p style="font-family:' + (Get-PimMailBrand).font + ';font-size:14px;margin:10px 0 0 0;">' + (ConvertTo-PimMailText ("{0} people hold Tier 0 or Tier 1 access: {1} at Tier 0, {2} at Tier 1. Review anyone you do not expect." -f $rep.Count, $t0.Count, $t1.Count)) + '</p>'
    $rows = @($rep | ForEach-Object { [pscustomobject]@{ user = $_.user; tier = ('Tier ' + [int]$_.highestTier); levels = $(if (@($_.levels).Count) { (@($_.levels | ForEach-Object { "L$_" }) -join ', ') } else { '' }); grants = [int]$_.grantCount
        groups = ((@($_.grants | ForEach-Object { "$($_.tag)" } | Where-Object { $_ } | Select-Object -Unique) | Select-Object -First 6) -join ', ') } })
    $cols = @(@{ key = 'user'; label = 'Person' }, @{ key = 'tier'; label = 'Highest tier' }, @{ key = 'levels'; label = 'Level(s)' }, @{ key = 'grants'; label = 'Grants' }, @{ key = 'groups'; label = 'Groups' })
    $body = New-PimMailSection -Title ("Tier 0 ({0})" -f $t0.Count) -Html (New-PimMailTable -Columns $cols -Rows @($rows | Where-Object { $_.tier -eq 'Tier 0' }) -EmptyText 'Nobody holds Tier 0 access.' -MaxRows $(if ($Print) { 0 } else { 60 }) -MoreUrl $btn.url)
    $body += New-PimMailSection -Title ("Tier 1 ({0})" -f $t1.Count) -Html (New-PimMailTable -Columns $cols -Rows @($rows | Where-Object { $_.tier -eq 'Tier 1' }) -EmptyText 'Nobody holds Tier 1 access.' -MaxRows $(if ($Print) { 0 } else { 60 }) -MoreUrl $btn.url)
    $t['ReportHtml'] = New-PimMailDocument -Title 'Tier 0 / Tier 1 access' -Subtitle ('as of ' + $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC') -Preheader ("{0} Tier 0 and {1} Tier 1 holders" -f $t0.Count, $t1.Count) `
        -SummaryHtml $sum -BodyHtml $body -Button $(if ($btn.url) { @{ url = $btn.url; label = $btn.label } } else { $null }) -HomeUrl $homeUrl -NotificationsUrl $notif `
        -Environment $Environment -AudienceLabel (Get-PimMailAudienceLabel $Audience) -GeneratedUtc $NowUtc -Print:$Print
    return $t
}

# ---------------------------------------------------------------------------
# DATA SOURCES for the daily-summary / tier-report JOBS -- SQL, not globals or files.
# Both jobs reported ran=true over inputs nothing supplied: $global:PIM_TierReportAssignments and
# $global:PIM_DigestRecipients were never set by anything, and the daily summary read an audit
# JSONL FILE the hosted runtime never writes (the trail is pim.AuditEvents since SEC-16).
# A launcher that still injects the globals wins, so an existing wiring keeps working.
# ---------------------------------------------------------------------------
function Get-PimNotifySqlConnectionString {
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) {
        try { $cs = Get-PimSqlSettingsConnectionString; if ("$cs".Trim()) { return "$cs" } } catch { }
    }
    return ''
}

function Get-PimDailySummaryEventsFromStore {
    <#
      The audit events for the daily summary window, from pim.AuditEvents (Get-PimSqlAuditEvents).
      Returns @{ ok; events; source; error }. ok=$false = the trail could not be read.
    #>
    [CmdletBinding()]
    param([datetime]$NowUtc = [datetime]::UtcNow, [int]$WindowHours = 24)
    if ($null -ne $global:PIM_SummaryEvents) {
        return [pscustomobject]@{ ok = $true; events = @($global:PIM_SummaryEvents); source = 'injected'; error = '' }
    }
    if (-not (Get-Command Get-PimSqlAuditEvents -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ok = $false; events = @(); source = ''; error = 'the SQL audit reader (Get-PimSqlAuditEvents, PIM-SqlStore.ps1) is not loaded in this process' }
    }
    $cs = Get-PimNotifySqlConnectionString
    if (-not $cs) { return [pscustomobject]@{ ok = $false; events = @(); source = ''; error = 'no SQL connection string in this process, so the audit trail cannot be read' } }
    $end = $NowUtc.ToUniversalTime()
    try {
        $ev = @(Get-PimSqlAuditEvents -ConnectionString $cs -FromUtc $end.AddHours(-[math]::Abs($WindowHours)) -ToUtc $end -Top 5000)
        return [pscustomobject]@{ ok = $true; events = $ev; source = 'sql:pim.AuditEvents'; error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; events = @(); source = ''; error = "audit trail read failed: $($_.Exception.Message)" }
    }
}

function Get-PimDigestRecipients {
    <#
      Who receives a digest. pim.Settings['Alerting'] -- the SAME document the Manager's Alerting card
      saves and the scheduler's job alerts read -- gives the recipients: 'digestRecipients' (daily
      summary) or 'tierReportRecipients' (tier report) when present, else the alerting 'recipients'.
      An injected global ($global:PIM_DigestRecipients / PIM_TierReportRecipients) still wins.
      Returns @{ recipients; source }.
    #>
    [CmdletBinding()]
    # 'alerts' (MAIL-2 item 8, the Get Started reminder): the alert recipients only -- no report-specific list.
    param([ValidateSet('daily-summary','tier-report','alerts')][string]$Kind = 'daily-summary')
    $g = if ($Kind -eq 'tier-report') { $global:PIM_TierReportRecipients } elseif ($Kind -eq 'alerts') { $null } else { $global:PIM_DigestRecipients }
    $inj = @(@($g) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($inj.Count) { return [pscustomobject]@{ recipients = $inj; source = 'injected' } }
    $raw = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $raw = Get-PimSetting -Name 'Alerting' } catch { $raw = $null }
    } else {
        $cs = Get-PimNotifySqlConnectionString
        if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { try { $raw = Get-PimSqlSetting -ConnectionString $cs -Name 'Alerting' } catch { $raw = $null } }
    }
    for ($i = 0; $i -lt 2 -and $raw -is [string]; $i++) { if ("$raw".Trim()) { try { $raw = $raw | ConvertFrom-Json } catch { $raw = $null } } else { $raw = $null } }
    if ($null -eq $raw) { return [pscustomobject]@{ recipients = @(); source = 'none' } }
    $specific = if ($Kind -eq 'tier-report') { 'tierReportRecipients' } elseif ($Kind -eq 'alerts') { 'recipients' } else { 'digestRecipients' }
    foreach ($name in @($specific, 'recipients')) {
        $v = $null
        if ($raw -is [System.Collections.IDictionary]) { if ($raw.Contains($name)) { $v = $raw[$name] } }
        else { $p = $raw.PSObject.Properties[$name]; if ($p) { $v = $p.Value } }
        $list = @(@($v) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if ($list.Count) { return [pscustomobject]@{ recipients = $list; source = "sql:Alerting.$name" } }
    }
    return [pscustomobject]@{ recipients = @(); source = 'sql:Alerting (no recipients)' }
}

function Get-PimTierReportAssignmentsFromStore {
    <#
      The tier-report input from SQL: every admin -> PIM group assignment (PIM-Assignments-Admins,
      Action != Remove), with the group's tier and level taken from the row, else from the group's
      DEFINITION row (TierLevel / Level), else from the name markers Get-PimRowTier reads.

      LIVE: the verify-convergence job records, per desired admin membership, whether Entra holds it
      (pim.Settings['ConvergenceState']). Each grant is marked:
        verified      -- the AdminMembers scope was last verified with nothing unconverged
        not-deployed  -- this grant is listed as desired-but-not-live
        unverified    -- no verification result to go on
      Returns @{ ok; rows; read; live = @{ checkedUtc; unconverged }; error }.
    #>
    [CmdletBinding()]
    param()
    if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ok = $false; rows = @(); read = 0; live = $null; error = 'the desired-row reader (Get-PimDesiredRows, PIM-EngineCore.ps1) is not loaded in this process' }
    }
    $asg = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Admins')
    $resolved = ($global:PIM_DesiredResolved -is [hashtable]) -and $global:PIM_DesiredResolved.ContainsKey('PIM-Assignments-Admins') -and [bool]$global:PIM_DesiredResolved['PIM-Assignments-Admins']
    if (-not $resolved) {
        return [pscustomobject]@{ ok = $false; rows = @(); read = 0; live = $null; error = 'PIM-Assignments-Admins could not be read (no SQL store wired, or the read failed)' }
    }
    # tag -> definition (tier / level / name)
    $defs = @{}
    foreach ($e in @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','PIM-Definitions-Departments','PIM-Definitions-Processes','PIM-Definitions-Projects','PIM-Definitions-CrossOrg','PIM-Definitions-Resources')) {
        foreach ($d in @(Get-PimDesiredRows -Entity $e)) {
            if ($null -eq $d) { continue }
            $t = Get-PimNotifyField -Item $d -Name 'GroupTag'
            if ("$t".Trim() -and -not $defs.ContainsKey("$t".Trim().ToLowerInvariant())) { $defs["$t".Trim().ToLowerInvariant()] = $d }
        }
    }
    # live verification (ConvergenceState, written by verify-convergence)
    $conv = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $conv = Get-PimSetting -Name 'ConvergenceState' } catch { $conv = $null } }
    for ($i = 0; $i -lt 2 -and $conv -is [string]; $i++) { if ("$conv".Trim()) { try { $conv = $conv | ConvertFrom-Json } catch { $conv = $null } } else { $conv = $null } }
    $adminCache = $null; $pending = @()
    if ($null -ne $conv) {
        $cache = $conv.cache; if ($null -ne $cache) { $adminCache = $cache.AdminMembers }
        $fs = $conv.firstSeen
        if ($null -ne $fs) { $pending = @($fs.PSObject.Properties | Where-Object { "$($_.Name)" -like 'AdminMembers|*' } | ForEach-Object { "$($_.Name)".ToLowerInvariant() }) }
    }
    $verified = ($null -ne $adminCache) -and ("$($adminCache.unconverged)" -eq '0')
    $rows = New-Object System.Collections.ArrayList
    foreach ($r in $asg) {
        if ($null -eq $r) { continue }
        if ((Get-PimNotifyField -Item $r -Name 'Action') -eq 'Remove') { continue }
        $user = Get-PimNotifyField -Item $r -Name 'Username'; if (-not "$user".Trim()) { $user = Get-PimNotifyField -Item $r -Name 'UserName' }
        $tag = Get-PimNotifyField -Item $r -Name 'GroupTag'
        if (-not "$user".Trim() -or -not "$tag".Trim()) { continue }
        $def = $defs["$tag".Trim().ToLowerInvariant()]
        $tier = Get-PimNotifyField -Item $r -Name 'TierLevel'
        if (-not "$tier".Trim() -and $def) { $tier = Get-PimNotifyField -Item $def -Name 'TierLevel' }
        $level = Get-PimNotifyField -Item $r -Name 'Level'
        if (-not "$level".Trim() -and $def) { $level = Get-PimNotifyField -Item $def -Name 'Level' }
        $type = Get-PimNotifyField -Item $r -Name 'AssignmentType'
        $live = if ($verified) { 'verified' } else { 'unverified' }
        if ($pending.Count) {
            $suffix = ("|{0}|{1}" -f "$tag".Trim(), "$type".Trim()).ToLowerInvariant()
            $hits = @($pending | Where-Object { $_.EndsWith($suffix) })
            if ($hits.Count) {
                $live = 'unverified'
                if (Get-Command Resolve-PimPrincipalId -ErrorAction SilentlyContinue) {
                    try {
                        $pid2 = Resolve-PimPrincipalId $user
                        if ($pid2 -and ($hits -contains ("adminmembers|{0}{1}" -f "$pid2".ToLowerInvariant(), $suffix))) { $live = 'not-deployed' }
                    } catch { }
                }
            }
        }
        $row = [ordered]@{ UserName = "$user".Trim(); GroupTag = "$tag".Trim(); AssignmentType = "$type"; Live = $live }
        if ("$tier".Trim())  { $row['TierLevel'] = "$tier".Trim() }
        if ("$level".Trim()) { $row['Level'] = "$level".Trim() }
        if ($def) { $row['GroupName'] = (Get-PimNotifyField -Item $def -Name 'GroupName') }
        [void]$rows.Add([pscustomobject]$row)
    }
    $liveInfo = [pscustomobject]@{
        checkedUtc  = $(if ($adminCache) { "$($adminCache.checkedUtc)" } else { '' })
        unconverged = $(if ($adminCache) { "$($adminCache.unconverged)" } else { '' })
    }
    return [pscustomobject]@{ ok = $true; rows = $rows.ToArray(); read = $asg.Count; live = $liveInfo; error = '' }
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
    $req = Get-PimUtcStamp $reqRaw   # IMP-02
    if ($null -eq $req) { return $null }
    $elapsed = ($NowUtc.ToUniversalTime() - $req).TotalHours
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

# ---- store-and-forward broker: SQL pim.Settings['IntakeRequests'] ONLY ----------
# 🔴 BUG-211 (§33.28): the drop store was a JSONL FILE ($global:PIM_IntakeStoreFile) -- a file PIM v2 does not have
# in a container -- and the job returned ran=$true with routing DECISIONS that nothing acted on: an 'approve' never
# became a request and an 'auto-apply' never became a change. Now:
#   * the drop store is pim.Settings['IntakeRequests'] (Add-PimIntakeRecord appends; the store THROWS on failure);
#   * Invoke-PimIntakeProcess ACTS on every received record and records the outcome ON the record, so a record is
#     processed exactly once: 'reject' -> status rejected (+reason); 'approve' / 'auto-apply' -> a PENDING proposal in
#     pim.ChangeQueue (de-duplicated) that an operator reviews and commits in Pending changes -> status queued.
#     🔒 'auto-apply' is NOT committed by the machine: §65.7 -- origin never grants the right to apply, the commit does.
#     The allowlist only changes the reason text ("allowlisted") so a reviewer can bulk-commit with confidence;
#   * a request type PIM cannot map to a desired-state row -> status unsupported (+reason), and the job says so.
# The integration is "configured" when the setting 'IntakeEnabled' is true. Resolution order:
#   1. $global:PIM_IntakeEnabled (a runtime override: tests, a launcher);
#   2. pim.Settings['IntakeEnabled'] (THE v2 home -- the store both containers read; true/false, or {"enabled":true});
#   3. the policy value (Get-PimPolicySetting: the naming config key, or env PIM_IntakeEnabled on the container).
# 🔴 §33.28 integration: this comment used to say "pim.Settings", but nothing read pim.Settings -- the only ways to turn
# the intake on in a hosted tick were an env var or a config key. A store that cannot be read leaves the integration
# OFF and says so (the job then reports "not enabled", never a silent drain of a store it cannot see).
function Test-PimIntakeConfigured {
    [CmdletBinding()] param()
    if ($null -ne $global:PIM_IntakeEnabled -and "$($global:PIM_IntakeEnabled)".Trim()) { return ("$($global:PIM_IntakeEnabled)".Trim() -match '^(?i)(true|1|yes|on)$') }
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        $sv = $null
        try { $sv = Get-PimSetting -Name 'IntakeEnabled' }
        catch { Write-Warning "[intake] pim.Settings['IntakeEnabled'] could not be read ($($_.Exception.Message)) -- ServiceNow intake stays OFF this run."; return $false }
        if ($null -ne $sv) {
            if ($sv -is [bool]) { return [bool]$sv }
            if ($sv.PSObject -and $sv.PSObject.Properties['enabled']) { $sv = $sv.enabled }
            if ("$sv".Trim()) { return ("$sv".Trim() -match '^(?i)(true|1|yes|on)$') }
        }
    }
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimPolicySetting -Name 'IntakeEnabled' -Default $null; if ($null -ne $v) { return ("$v".Trim() -match '^(?i)(true|1|yes|on)$') } } catch { }
    }
    return $false
}

function Get-PimIntakeRequests {
    # All intake records in the drop store. THROWS when no store is wired or it cannot be read.
    [CmdletBinding()] param()
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { throw 'intake store unavailable: no SQL settings store (Get-PimSetting) is wired -- PIM v2 keeps intake requests in SQL only' }
    $v = Get-PimSetting -Name 'IntakeRequests'
    if ($null -eq $v) { return @() }
    if ($v -is [string]) { if (-not "$v".Trim()) { return @() }; $v = $v | ConvertFrom-Json }
    return @(@($v) | Where-Object { $null -ne $_ })
}

function Save-PimIntakeRequests {
    [CmdletBinding()] param([object[]]$Records = @())
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw 'intake store unavailable: no SQL settings store (Set-PimSetting) is wired' }
    $json = ConvertTo-Json -InputObject @(@($Records) | Where-Object { $null -ne $_ }) -Depth 8 -Compress
    if (-not $json -or $json -eq 'null') { $json = '[]' }
    Set-PimSetting -Name 'IntakeRequests' -Value $json
}

function Add-PimIntakeRecord {
    # Append a SANITISED intake record to the drop store (what the external side does). THROWS on a store failure.
    param([Parameter(Mandatory)][object]$Record)
    $clean = ConvertTo-PimIntakeRecord -Payload $Record
    if (-not $clean) { throw 'intake record refused: requestType and requestor are mandatory' }
    Save-PimIntakeRequests -Records (@(Get-PimIntakeRequests) + @($clean))
    return $clean
}

function Invoke-PimIntakePoll {
    # PURE routing over records (no store, no apply): sanitise + route every RECEIVED record. Records already
    # carrying a non-'received' status are skipped (idempotent). -Records defaults to the SQL drop store.
    param([object[]]$Records, [datetime]$NowUtc = [datetime]::UtcNow, [string[]]$AutoApplyTypes)
    if (-not $PSBoundParameters.ContainsKey('Records')) { $Records = @(Get-PimIntakeRequests) }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($raw in @($Records)) {
        if ($null -eq $raw) { continue }
        $st = (Get-PimNotifyField -Item $raw -Name 'status')
        if ($st -and $st -ne 'received') { continue }
        $rec = ConvertTo-PimIntakeRecord -Payload $raw -NowUtc $NowUtc
        if (-not $rec) { $results.Add([pscustomobject]@{ route = 'reject'; reason = 'malformed record'; record = $raw; source = $raw }); continue }
        $route = Resolve-PimIntakeRouting -Record $rec -AutoApplyTypes $AutoApplyTypes
        $results.Add([pscustomobject]@{ route = $route.route; reason = $route.reason; record = $rec; source = $raw })
    }
    return $results.ToArray()
}

function ConvertTo-PimIntakeChange {
    # PURE-ish: an accepted intake record -> the desired-state row it asks for, or $null when PIM cannot map the
    # request type. Supported: an admin into a PIM group (group-add / delegation-request / group-membership /
    # admin-group-assignment) -> PIM-Assignments-Admins { Username; GroupTag; AssignmentType=Eligible }.
    param([Parameter(Mandatory)][object]$Record, [string]$Justification = '')
    $type = (Get-PimNotifyField -Item $Record -Name 'requestType').ToLowerInvariant()
    $who  = (Get-PimNotifyField -Item $Record -Name 'targetAdmin').Trim()
    $tag  = (Get-PimNotifyField -Item $Record -Name 'groupTag').Trim()
    if ($type -notin @('group-add','delegation-request','group-membership','admin-group-assignment')) { return $null }
    if (-not $who -or -not $tag) { return $null }
    $row = [pscustomobject]@{ Username = $who; GroupTag = $tag; AssignmentType = 'Eligible' }
    $key = if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { Get-PimStoreRowKey -Base 'PIM-Assignments-Admins' -Row $row } else { "$who|$tag" }
    if (-not "$key".Trim()) { return $null }
    return (New-PimChange -Entity 'PIM-Assignments-Admins' -Key "$key" -Op Create -Payload $row -By 'servicenow-intake' -Justification $Justification)
}

function Invoke-PimIntakeProcess {
    <#
      BUG-211: poll the SQL drop store and ACT on every received record (see the block comment above). Returns
      @{ ran; detail; queued; rejected; unsupported; duplicates }. THROWS when the store or the change queue cannot
      be reached -- the job then FAILS; a record is marked only after its proposal is written.
    #>
    [CmdletBinding()] param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string[]]$AutoApplyTypes)
    $all = @(Get-PimIntakeRequests)
    $decisions = @(Invoke-PimIntakePoll -Records $all -NowUtc $NowUtc -AutoApplyTypes $AutoApplyTypes)
    $cnt = @{ queued = 0; rejected = 0; unsupported = 0; duplicates = 0 }
    if (-not $decisions.Count) { return [pscustomobject]@{ ran = $false; nothingDue = $true; detail = ("intake: no new requests ({0} in the store)" -f $all.Count); queued = 0; rejected = 0; unsupported = 0; duplicates = 0 } }
    if ($WhatIf) { return [pscustomobject]@{ ran = $true; whatIf = $true; detail = ("intake (whatif): {0} new request(s) would be processed" -f $decisions.Count); decisions = $decisions } }
    $cs = "$($global:PIM_SqlConnectionString)"; if (-not $cs.Trim() -and "$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
    foreach ($d in $decisions) {
        $src = $d.source
        $mark = @{ status = ''; processedUtc = $NowUtc.ToUniversalTime().ToString('o'); outcome = '' }
        if ($d.route -eq 'reject') {
            $mark.status = 'rejected'; $mark.outcome = "$($d.reason)"; $cnt.rejected++
        } else {
            $just = "ServiceNow $((Get-PimNotifyField -Item $d.record -Name 'externalId')): $((Get-PimNotifyField -Item $d.record -Name 'justification')) ($($d.reason))".Trim()
            $ch = ConvertTo-PimIntakeChange -Record $d.record -Justification $just
            if (-not $ch) {
                $mark.status = 'unsupported'; $mark.outcome = "request type '$((Get-PimNotifyField -Item $d.record -Name 'requestType'))' (or its targetAdmin/groupTag) cannot be mapped to a desired-state change -- handle it by hand"; $cnt.unsupported++
            } else {
                if (-not $cs.Trim() -or -not (Get-Command Add-PimSqlQueueChangeIfAbsent -ErrorAction SilentlyContinue)) { throw 'intake: no SQL change queue is wired -- the request cannot be queued (nothing was marked processed)' }
                $added = Add-PimSqlQueueChangeIfAbsent -ConnectionString $cs -Change $ch
                if (-not $added) { $cnt.duplicates++ }
                $mark.status = 'queued'; $mark.outcome = ("pending change {0}/{1} for review in Pending changes{2}" -f $ch.entity, $ch.key, $(if ($added) { '' } else { ' (already open -- not added again)' })); $cnt.queued++
            }
        }
        foreach ($k in @($mark.Keys)) { $src | Add-Member -NotePropertyName $k -NotePropertyValue $mark[$k] -Force }
    }
    Save-PimIntakeRequests -Records $all
    $detail = ("intake: queued={0} (for review -- never auto-committed) rejected={1} unsupported={2} duplicates={3}" -f $cnt.queued, $cnt.rejected, $cnt.unsupported, $cnt.duplicates)
    return [pscustomobject]@{ ran = $true; detail = $detail; queued = $cnt.queued; rejected = $cnt.rejected; unsupported = $cnt.unsupported; duplicates = $cnt.duplicates }
}
