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
        if ("$v".Trim()) { $d = [datetime]::MinValue; if ([datetime]::TryParse("$v", [ref]$d)) { return $d.ToUniversalTime() } }
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
        $last = [datetime]::MinValue
        if ([datetime]::TryParse("$LastNotifiedUtc", [ref]$last)) {
            if (($NowUtc - $last.ToUniversalTime()).TotalDays -ge $interval) {
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

function New-PimRenewalChange {
    # Change-queue Update that extends an item's expiry date field.
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$DateField, [Parameter(Mandatory)][string]$NewExpiryUtc, [string]$By = 'auto-renew')
    return New-PimChange -Entity $Entity -Key $Key -Op Update -By $By -Payload ([pscustomobject]@{ ($DateField) = $NewExpiryUtc; AutoRenewed = $true })
}
