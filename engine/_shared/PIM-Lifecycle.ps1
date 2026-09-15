# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
# PIM4EntraPS -- lifecycle calendar: upcoming expirations, auto-renew, escalation.
# Dot-sourced by PIM-Functions.psm1 (uses PIM-ChangeQueue.ps1 + Get-PimPolicySetting)
# and the pim-manager.
#
# Surfaces scheduled/upcoming expirations + auto-renewals across admins,
# consultants, access reviews and assignments, and decides which escalation
# notifications are due (configurable stage thresholds + per-stage recipients +
# reminder resends). Pure (time injected) so it is fully testable; the actual mail
# send is a thin wrapper over the existing templated mail, and auto-renewals/
# removals feed the change queue.

Set-StrictMode -Off

# Date fields we look at, in priority order (configurable via -DateFields or
# $global config key 'LifecycleDateFields').
function Get-PimLifecycleDateFields {
    $cfg = $null
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $cfg = Get-PimPolicySetting -Name 'LifecycleDateFields' -Default $null }
    if ($cfg) { return @($cfg) }
    return @('ExpiresUtc','expiresUtc','OffboardDate','ExpirationDate','ReviewDueUtc','DeleteDate')
}

function Resolve-PimExpiryDate {
    # First parseable date among the candidate fields -> [datetime] (UTC) or $null.
    param([Parameter(Mandatory)][object]$Item, [string[]]$DateFields)
    if (-not $DateFields) { $DateFields = Get-PimLifecycleDateFields }
    foreach ($f in @($DateFields)) {
        $v = $null
        if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($f)) { $v = "$($Item[$f])" } }
        else { $p = $Item.PSObject.Properties[$f]; if ($p) { $v = "$($p.Value)" } }
        if ("$v".Trim()) { $d = Get-PimUtcStamp $v; if ($null -ne $d) { return $d } }   # IMP-02
    }
    return $null
}

function Get-PimDaysLeft {
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][datetime]$NowUtc, [string[]]$DateFields)
    $exp = Resolve-PimExpiryDate -Item $Item -DateFields $DateFields
    if ($null -eq $exp) { return $null }
    return [int][math]::Floor(($exp - $NowUtc).TotalDays)
}

function Get-PimUpcomingExpirations {
    # Items expiring within $HorizonDays (incl. already-expired when -IncludeExpired).
    # Returns each item annotated with ExpiryUtc + DaysLeft, soonest first.
    param([object[]]$Items = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$HorizonDays = 30, [string[]]$DateFields, [switch]$IncludeExpired)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($it in @($Items)) {
        $exp = Resolve-PimExpiryDate -Item $it -DateFields $DateFields
        if ($null -eq $exp) { continue }
        $days = [int][math]::Floor(($exp - $NowUtc).TotalDays)
        if ($days -gt $HorizonDays) { continue }
        if ($days -lt 0 -and -not $IncludeExpired) { continue }
        $out.Add([pscustomobject]@{ item = $it; expiryUtc = $exp.ToString('o'); daysLeft = $days })
    }
    return @($out.ToArray() | Sort-Object daysLeft)
}

# --- escalation policy (configurable) -------------------------------------------
function Get-PimDefaultEscalationPolicy {
    # Stage thresholds (days before expiry) + per-stage recipients, plus a reminder
    # resend interval. Override via config key 'EscalationPolicy'.
    return [pscustomobject]@{
        stages = @(
            [pscustomobject]@{ atDays = 30; recipients = @('owner') }
            [pscustomobject]@{ atDays = 14; recipients = @('owner') }
            [pscustomobject]@{ atDays = 7;  recipients = @('owner','manager') }
            [pscustomobject]@{ atDays = 1;  recipients = @('owner','manager','admin') }
        )
        reminderIntervalDays = 3
    }
}

function Get-PimEscalationPolicy {
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $cfg = Get-PimPolicySetting -Name 'EscalationPolicy' -Default $null
        if ($cfg) { return $cfg }
    }
    return Get-PimDefaultEscalationPolicy
}

function Get-PimDueEscalation {
    # Which escalation notification is due NOW for an item with $DaysLeft, given the
    # policy + when it was last notified at which stage. Returns
    # @{ stage; recipients; isReminder } or $null (nothing due). A new stage fires
    # immediately; the same stage re-fires only after reminderIntervalDays.
    param(
        [Parameter(Mandatory)][int]$DaysLeft, [Parameter(Mandatory)][datetime]$NowUtc,
        [object]$Policy, [Nullable[int]]$LastStageAtDays, [string]$LastNotifiedUtc
    )
    if (-not $Policy) { $Policy = Get-PimEscalationPolicy }
    # most-urgent crossed stage = smallest atDays that is still >= DaysLeft
    $current = $null
    foreach ($s in @($Policy.stages)) {
        if ([int]$s.atDays -ge $DaysLeft) { if ($null -eq $current -or [int]$s.atDays -lt [int]$current.atDays) { $current = $s } }
    }
    if (-not $current) { return $null }
    $cur = [int]$current.atDays
    if ($null -eq $LastStageAtDays -or [int]$LastStageAtDays -ne $cur) {
        return [pscustomobject]@{ stage = $cur; recipients = @($current.recipients); isReminder = $false }
    }
    $interval = if ($Policy.reminderIntervalDays) { [int]$Policy.reminderIntervalDays } else { 0 }
    if ($interval -gt 0 -and "$LastNotifiedUtc".Trim()) {
        $last = Get-PimUtcStamp $LastNotifiedUtc   # IMP-02
        if ($null -ne $last) {
            if (($NowUtc - $last).TotalDays -ge $interval) {
                return [pscustomobject]@{ stage = $cur; recipients = @($current.recipients); isReminder = $true }
            }
        }
    }
    return $null
}

# --- auto-renew -----------------------------------------------------------------
function Get-PimAutoRenewal {
    # An item with a truthy AutoExtend (column) within $RenewWithinDays of expiry ->
    # a renewal to NowUtc + $ExtendDays. Returns @{ renew; newExpiryUtc } or null.
    param(
        [Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][datetime]$NowUtc,
        [int]$RenewWithinDays = 7, [int]$ExtendDays = 90, [string[]]$DateFields, [string]$AutoExtendField = 'AutoExtend'
    )
    $ae = $null
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($AutoExtendField)) { $ae = "$($Item[$AutoExtendField])" } }
    else { $p = $Item.PSObject.Properties[$AutoExtendField]; if ($p) { $ae = "$($p.Value)" } }
    if ("$ae".Trim().ToLowerInvariant() -notin @('true','1','yes','y')) { return $null }
    $days = Get-PimDaysLeft -Item $Item -NowUtc $NowUtc -DateFields $DateFields
    if ($null -eq $days -or $days -gt $RenewWithinDays) { return $null }
    return [pscustomobject]@{ renew = $true; newExpiryUtc = $NowUtc.AddDays($ExtendDays).ToString('o'); daysLeft = $days }
}

# --- lifecycle items FROM THE STORE (the 'reminders' job's data source) ------------
# The date-expression resolver is loaded defensively: the scheduler tick does not dot-source
# PIM-DateExpression.ps1, and without it every OffboardDate expression would be unreadable.
if (-not (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) -and $PSScriptRoot) {
    $__pimDateExpr = Join-Path $PSScriptRoot 'PIM-DateExpression.ps1'
    if (Test-Path -LiteralPath $__pimDateExpr) { . $__pimDateExpr }
}

function ConvertTo-PimLifecycleUtc {
    # A lifecycle cell (date expression or plain date) -> UTC [datetime], or $null.
    param([string]$Value)
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) {
        try { return ([datetime](Resolve-PimDateExpression -Expression $s)).ToUniversalTime() } catch { }
    }
    return (Get-PimUtcStamp $s)
}

function Get-PimLifecycleItemsFromStore {
    <#
      The lifecycle items the calendar works on, read from the DESIRED rows in SQL (pim.Rows via
      Get-PimDesiredRows) -- the data the 'reminders' job was declared over and never received
      ($global:PIM_LifecycleItems was never set by anything).

      What v1 had: no reminder job. Its lifecycle dates were acted on, not announced -- OffboardDate
      (a date expression) triggered the revoke, DeleteAfterDays later the delete (PIM-Functions.psm1
      ~L10569-10573, ~L11011-11028), and an assignment's live end date drove AutoExtend
      (~L4647-4677). The dates that live in DESIRED state are the admin ones, so those are the items:
        * admin-offboard  -- Account-Definitions-Admins.OffboardDate
        * admin-delete    -- OffboardDate + DeleteAfterDays
        * <entity>        -- any assignment row that carries an explicit lifecycle date column
                             (Get-PimLifecycleDateFields). NumOfDaysWhenExpire is a DURATION and the
                             real end date is only in the live schedule, so it is not guessed here.
      Rows further than -PastDays in the past are dropped: an admin offboarded months ago is history,
      not a reminder.

      Returns @{ ok; items; read = @{ entity = count }; unresolved = @(entities); unparseable; error }.
      ok=$false means the store could not be read -- "cannot answer", never "nothing due".
    #>
    [CmdletBinding()]
    param([datetime]$NowUtc = [datetime]::UtcNow, [int]$PastDays = 30)
    $out = [ordered]@{ ok = $false; items = @(); read = [ordered]@{}; unresolved = @(); unparseable = 0; error = '' }
    if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) {
        $out.error = 'the desired-row reader (Get-PimDesiredRows, PIM-EngineCore.ps1) is not loaded in this process'
        return [pscustomobject]$out
    }
    $now = $NowUtc.ToUniversalTime()
    $floor = $now.AddDays(-[math]::Abs($PastDays))
    $items = New-Object System.Collections.ArrayList
    $unresolved = New-Object System.Collections.ArrayList
    $bad = 0
    $entities = @('Account-Definitions-Admins','PIM-Assignments-Admins','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads')
    $dateFields = @(Get-PimLifecycleDateFields | Where-Object { "$_" -notin @('OffboardDate','DeleteDate') })
    foreach ($ent in $entities) {
        $rows = @(Get-PimDesiredRows -Entity $ent)
        $resolved = ($global:PIM_DesiredResolved -is [hashtable]) -and $global:PIM_DesiredResolved.ContainsKey($ent) -and [bool]$global:PIM_DesiredResolved[$ent]
        if (-not $resolved) { [void]$unresolved.Add($ent); continue }
        $out.read[$ent] = $rows.Count
        foreach ($r in $rows) {
            if ($null -eq $r) { continue }
            $get = { param($names) foreach ($n in $names) { if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n) -and "$($r[$n])".Trim()) { return "$($r[$n])".Trim() } } else { $p = $r.PSObject.Properties[$n]; if ($p -and "$($p.Value)".Trim()) { return "$($p.Value)".Trim() } } }; return '' }
            if ($ent -eq 'Account-Definitions-Admins') {
                $user = & $get @('UserPrincipalName','UserName')
                $off = & $get @('OffboardDate')
                if (-not $off) { continue }
                $offUtc = ConvertTo-PimLifecycleUtc -Value $off
                if ($null -eq $offUtc) { $bad++; continue }
                $mgr = & $get @('ManagerEmail')
                if ($offUtc -ge $floor) {
                    [void]$items.Add([pscustomobject]@{ Id = "admin-offboard:$user"; Kind = 'admin-offboard'; UserName = $user; ExpiresUtc = $offUtc.ToString('o'); ManagerEmail = $mgr; Entity = $ent })
                }
                $dd = & $get @('DeleteAfterDays')
                $n = 0
                if ($dd -and [int]::TryParse($dd, [ref]$n) -and $n -gt 0) {
                    $delUtc = $offUtc.AddDays($n)
                    if ($delUtc -ge $floor) {
                        [void]$items.Add([pscustomobject]@{ Id = "admin-delete:$user"; Kind = 'admin-delete'; UserName = $user; ExpiresUtc = $delUtc.ToString('o'); ManagerEmail = $mgr; Entity = $ent })
                    }
                }
                continue
            }
            $dv = & $get $dateFields
            if (-not $dv) { continue }
            $du = ConvertTo-PimLifecycleUtc -Value $dv
            if ($null -eq $du) { $bad++; continue }
            if ($du -lt $floor) { continue }
            $who = & $get @('Username','UserName','SourceGroupTag','GroupTag')
            $what = & $get @('GroupTag','TargetGroupTag','RoleDefinitionName','AzScopePermission','RoleName')
            [void]$items.Add([pscustomobject]@{ Id = "${ent}:$who|$what"; Kind = $ent; UserName = $who; GroupTag = $what; ExpiresUtc = $du.ToString('o'); AutoExtend = (& $get @('AutoExtend')); Entity = $ent })
        }
    }
    $out.items = $items.ToArray()
    $out.unresolved = $unresolved.ToArray()
    $out.unparseable = $bad
    if ($unresolved.Count -eq $entities.Count) {
        $out.error = 'no desired-state entity could be read (no SQL store wired, or the read failed)'
        return [pscustomobject]$out
    }
    $out.ok = $true
    return [pscustomobject]$out
}

function New-PimRenewalChange {
    # Change-queue Update that extends an item's expiry date field.
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$DateField, [Parameter(Mandatory)][string]$NewExpiryUtc, [string]$By = 'auto-renew')
    return New-PimChange -Entity $Entity -Key $Key -Op Update -By $By -Payload ([pscustomobject]@{ ($DateField) = $NewExpiryUtc; AutoRenewed = $true })
}
