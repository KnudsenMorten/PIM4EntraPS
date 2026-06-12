# PIM-DateExpression.ps1 -- shared date-expression resolver (LIFECYCLE-GOVERNANCE § 1).
# Dot-sourced by engine/_shared/PIM-Functions.psm1 AND by the pim-manager
# (Open-PimManager.ps1 / _validator.ps1), so the GUI preview, the validator,
# and the engine all resolve expressions identically. Pure function -- no
# module dependencies, PS 5.1 compatible.
#
# Grammar:
#   <expr> := Now
#           | <anchor>[<offset>][@<time>]
#           | <ISO date>[@<time>]            e.g. 2026-07-01@08:00
#   <anchor> := FirstDayNextMonth | FirstWorkdayNextMonth
#             | FirstDayNextWeek  | FirstWorkdayNextWeek
#   <offset> := +<n>d | -<n>d                (calendar days, applied AFTER the anchor resolves)
#   <time>   := HH:mm                        (tenant-local; omitted = 00:00)
#
# Workday = Mon-Fri (holiday calendars are a documented non-goal for now).

function Resolve-PimDateExpression {
    <#
    .SYNOPSIS
        Resolve a PIM date expression (Now / FirstWorkdayNextMonth-3d@08:00 /
        2026-07-01@08:00 / ...) to a UTC [datetime].

    .DESCRIPTION
        Times in the expression are interpreted as tenant-local and the result
        is returned as UTC. When the expression matches none of the grammar
        shapes, falls back to Resolve-PimTapStartDateTime (the v2.2.0
        natural-language resolver: 'in 2 days at 8am', 'tomorrow 9am', ...)
        when that function is loaded, then to a plain [datetime] cast --
        so every value that worked in existing CSVs keeps working. Throws
        with the grammar in the message when nothing can parse the input.

    .PARAMETER Expression
        The expression string (a CSV cell value).

    .PARAMETER ReferenceDate
        'Now' for anchor calculations -- injectable for tests. Local time.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Expression,
        [datetime]$ReferenceDate = (Get-Date)
    )

    $grammarHint = "Expected: Now | <anchor>[+/-Nd][@HH:mm] | yyyy-MM-dd[@HH:mm], where <anchor> is FirstDayNextMonth, FirstWorkdayNextMonth, FirstDayNextWeek or FirstWorkdayNextWeek (e.g. 'FirstWorkdayNextMonth-3d@08:00')."

    $s = $Expression.Trim()
    if (-not $s) { throw "Empty date expression. $grammarHint" }

    if ($s -match '^(?i)now$') {
        return [datetime]::SpecifyKind($ReferenceDate, [System.DateTimeKind]::Local).ToUniversalTime()
    }

    # Peel @HH:mm off the end
    $timeHour = 0; $timeMin = 0
    if ($s -match '^(.*?)\s*@\s*(\d{1,2}):(\d{2})$') {
        $s        = $Matches[1].Trim()
        $timeHour = [int]$Matches[2]
        $timeMin  = [int]$Matches[3]
        if ($timeHour -gt 23 -or $timeMin -gt 59) { throw "Invalid time '$timeHour`:$($Matches[3])' in date expression '$Expression'. $grammarHint" }
    }

    # Peel +Nd / -Nd off the end (anchors only -- an ISO date with an offset
    # is pointless, just write the date you mean)
    $offsetDays = 0
    $hasOffset  = $false
    if ($s -match '^(.*?)\s*([+-]\d+)\s*d$') {
        $s          = $Matches[1].Trim()
        $offsetDays = [int]$Matches[2]
        $hasOffset  = $true
    }

    $anchor = $null
    switch -regex ($s) {
        '^(?i)FirstDayNextMonth$' {
            $anchor = (Get-Date -Year $ReferenceDate.Year -Month $ReferenceDate.Month -Day 1).Date.AddMonths(1)
            break
        }
        '^(?i)FirstWorkdayNextMonth$' {
            $d = (Get-Date -Year $ReferenceDate.Year -Month $ReferenceDate.Month -Day 1).Date.AddMonths(1)
            while ($d.DayOfWeek -in @([System.DayOfWeek]::Saturday, [System.DayOfWeek]::Sunday)) { $d = $d.AddDays(1) }
            $anchor = $d
            break
        }
        '^(?i)(FirstDayNextWeek|FirstWorkdayNextWeek)$' {
            # Next Monday (strictly after the reference date's week position).
            # Both tokens resolve identically today (Monday IS a workday); they
            # stay distinct in the grammar for when holiday calendars land.
            $daysUntilMonday = ((7 - [int]$ReferenceDate.DayOfWeek + [int][System.DayOfWeek]::Monday) % 7)
            if ($daysUntilMonday -eq 0) { $daysUntilMonday = 7 }
            $anchor = $ReferenceDate.Date.AddDays($daysUntilMonday)
            break
        }
        '^\d{4}-\d{2}-\d{2}$' {
            try {
                $anchor = [datetime]::ParseExact($s, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
            } catch {
                throw "Invalid calendar date '$s' in date expression '$Expression'. $grammarHint"
            }
            if ($hasOffset) { throw "Offsets (+Nd/-Nd) only combine with anchors, not fixed dates -- write the date you mean. Expression: '$Expression'. $grammarHint" }
            break
        }
        default {
            # Not grammar -- fall back to the v2.2.0 natural-language resolver
            # (already UTC), then to a plain cast, so pre-existing CSV values
            # ('2026-07-01 08:00', 'tomorrow 9am', ...) keep working.
            if (Get-Command Resolve-PimTapStartDateTime -ErrorAction SilentlyContinue) {
                $legacy = $null
                try { $legacy = Resolve-PimTapStartDateTime -InputValue $Expression } catch { $legacy = $null }
                if ($legacy) { return $legacy }
            }
            try {
                return [datetime]::SpecifyKind(([datetime]$Expression), [System.DateTimeKind]::Local).ToUniversalTime()
            } catch {
                throw "Cannot parse date expression '$Expression'. $grammarHint"
            }
        }
    }

    $result = $anchor.Date.AddDays($offsetDays).AddHours($timeHour).AddMinutes($timeMin)
    return [datetime]::SpecifyKind($result, [System.DateTimeKind]::Local).ToUniversalTime()
}
