#Requires -Version 5.1
<#
  §82 CONSULTANT LIFECYCLE -- the PURE decision core of the company review (Pro). REQUIREMENTS §82.5-82.7.

  A Company (PIM-Definitions-Companies) has contact e-mails, a sponsor department and a review cadence. On the
  cadence the contacts get the list of THEIR consultants (admin rows with Company = that company) and answer per
  person: still working here / left / on leave until <date>. Any one contact may answer (operator 2026-10-02).
    * no answer: reminders on day 5 and day 10, escalation to the sponsor department on day 14, and on day 21 the
      still-unanswered consultants are DISABLED (AccountStatus=Disabled -- re-enabled through RFA). Never deleted.
    * left: disabled at once; the removal of memberships / eligibilities waits for an internal approver (it is the
      offboarding path, Lifecycle=Retire, raised as an approval request) -- "Disable now, remove later".
    * on leave until <date>: disabled now; the account stays as it is (RFA can enable it when they are back).
    * working: nothing changes.
  Everything here is PURE and PS 5.1-safe. Disable is AccountStatus=Disabled, NEVER AutoDisableDate (offboarding).
#>

$script:PimCompanyReviewDefaultCadenceDays = 90
$script:PimCompanyReviewRemindDays   = @(5, 10)
$script:PimCompanyReviewEscalateDay  = 14
$script:PimCompanyReviewDisableDay   = 21

function Get-PimCompanyRowValue {
    param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return "$($Row[$Name])".Trim() }; return '' }
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
}

function ConvertFrom-PimCompanyUtc {
    param([AllowNull()][object]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
    return $null
}

function Get-PimCompanyContacts {
    # PURE. The company's contact e-mails (pipe / comma / semicolon separated), lower-case, unique, valid only.
    param([Parameter(Mandatory)][object]$Company)
    return @(@((Get-PimCompanyRowValue -Row $Company -Name 'Contacts') -split '[|;,\s]+') |
        ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' } | Select-Object -Unique)
}

function Get-PimCompanyCadenceDays {
    param([Parameter(Mandatory)][object]$Company)
    $n = 0
    if ([int]::TryParse((Get-PimCompanyRowValue -Row $Company -Name 'ReviewCadenceDays'), [ref]$n) -and $n -ge 7 -and $n -le 366) { return $n }
    return $script:PimCompanyReviewDefaultCadenceDays
}

function Get-PimCompanyConsultants {
    # PURE. The admin rows linked to this company (Company column, case-insensitive), minus Revoked / retiring rows.
    param([Parameter(Mandatory)][object]$Company, [object[]]$Admins = @())
    $name = (Get-PimCompanyRowValue -Row $Company -Name 'Company').ToLowerInvariant()
    if (-not $name) { return @() }
    return @(@($Admins) | Where-Object {
        (Get-PimCompanyRowValue -Row $_ -Name 'Company').ToLowerInvariant() -eq $name -and
        (Get-PimCompanyRowValue -Row $_ -Name 'UserPrincipalName') -and
        (Get-PimCompanyRowValue -Row $_ -Name 'AccountStatus') -ine 'Revoked' -and
        (Get-PimCompanyRowValue -Row $_ -Name 'Lifecycle') -notmatch '(?i)^retire' })
}

function New-PimCompanyReviewCampaign {
    # PURE. A campaign for one company: the consultants at this moment, every item unanswered.
    param([Parameter(Mandatory)][object]$Company, [object[]]$Admins = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $items = @(Get-PimCompanyConsultants -Company $Company -Admins $Admins | ForEach-Object {
        [pscustomobject]@{ upn = (Get-PimCompanyRowValue -Row $_ -Name 'UserPrincipalName').ToLowerInvariant()
                           displayName = (Get-PimCompanyRowValue -Row $_ -Name 'DisplayName'); answer = ''; leaveUntil = ''; answeredBy = ''; answeredUtc = ''; applied = '' } })
    return [pscustomobject]@{
        id = [guid]::NewGuid().ToString('n'); company = (Get-PimCompanyRowValue -Row $Company -Name 'Company')
        sponsorDepartment = (Get-PimCompanyRowValue -Row $Company -Name 'SponsorDepartment')
        startedUtc = $now.ToString('o'); remindersSent = 0; escalatedUtc = ''; closedUtc = ''; items = $items
    }
}

function Get-PimCompanyReviewStep {
    <#
      PURE. What the company-review job does for one company now. Returns { action; reason }:
        start     no open campaign and the cadence is due (or none ever ran) -- and the company has consultants
        remind    open, day 5 / day 10 reached, that reminder not yet sent, something unanswered
        escalate  open, day 14 reached, not escalated, something unanswered -> mail the sponsor department's Owners
        disable   open, day 21 reached, something unanswered -> disable the unanswered (then close)
        close     open and everything answered
        none
      A company with no valid contact never starts (it is reported, not silently skipped).
    #>
    param([Parameter(Mandatory)][object]$Company, [AllowNull()][object]$Campaign, [AllowNull()][object]$LastClosedUtc,
          [int]$ConsultantCount = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    if ($null -eq $Campaign -or "$($Campaign.closedUtc)".Trim()) {
        # §89: an INTERNAL company is a label, not an external party -- it is never reviewed
        if ((Get-PimCompanyRowValue -Row $Company -Name 'Type') -match '^(?i)internal$') { return [pscustomobject]@{ action = 'none'; reason = 'an internal company is not reviewed' } }
        if ($ConsultantCount -lt 1) { return [pscustomobject]@{ action = 'none'; reason = 'no consultants linked to this company' } }
        if (-not @(Get-PimCompanyContacts -Company $Company).Count) { return [pscustomobject]@{ action = 'none'; reason = 'the company has no valid contact e-mail -- nobody can confirm its consultants (reported)' } }
        $last = ConvertFrom-PimCompanyUtc $LastClosedUtc
        if (-not $last -and $Campaign) { $last = ConvertFrom-PimCompanyUtc $Campaign.startedUtc }
        if (-not $last -or $now -ge $last.AddDays((Get-PimCompanyCadenceDays -Company $Company))) { return [pscustomobject]@{ action = 'start'; reason = 'the review is due' } }
        return [pscustomobject]@{ action = 'none'; reason = 'not due yet' }
    }
    $open = @(@($Campaign.items) | Where-Object { -not "$($_.answer)".Trim() })
    if (-not $open.Count) { return [pscustomobject]@{ action = 'close'; reason = 'every consultant is answered' } }
    $start = ConvertFrom-PimCompanyUtc $Campaign.startedUtc
    if (-not $start) { return [pscustomobject]@{ action = 'none'; reason = 'the campaign has no readable start' } }
    $age = ($now - $start).TotalDays
    if ($age -ge $script:PimCompanyReviewDisableDay) { return [pscustomobject]@{ action = 'disable'; reason = ("{0} consultant(s) unanswered after {1} days" -f $open.Count, $script:PimCompanyReviewDisableDay) } }
    if ($age -ge $script:PimCompanyReviewEscalateDay -and -not "$($Campaign.escalatedUtc)".Trim()) { return [pscustomobject]@{ action = 'escalate'; reason = ("{0} consultant(s) unanswered after {1} days" -f $open.Count, $script:PimCompanyReviewEscalateDay) } }
    $sent = [int]("0$($Campaign.remindersSent)")
    if ($sent -lt $script:PimCompanyReviewRemindDays.Count -and $age -ge $script:PimCompanyReviewRemindDays[$sent]) { return [pscustomobject]@{ action = 'remind'; reason = ("reminder {0} (day {1})" -f ($sent + 1), $script:PimCompanyReviewRemindDays[$sent]) } }
    return [pscustomobject]@{ action = 'none'; reason = 'waiting for answers' }
}

function Set-PimCompanyReviewAnswer {
    <#
      PURE. A contact's answer for one consultant. Returns { ok; reason; campaign }.
      -Answer working | left | leave (leave needs -LeaveUntil, a future date). Only a listed contact may answer, only
      while the campaign is open, only for a consultant on the list. A later answer replaces an earlier one until the
      engine has applied it.
    #>
    param([Parameter(Mandatory)][object]$Campaign, [Parameter(Mandatory)][object]$Company, [Parameter(Mandatory)][string]$Upn,
          [ValidateSet('working', 'left', 'leave')][string]$Answer, [string]$LeaveUntil = '', [Parameter(Mandatory)][string]$By,
          [datetime]$NowUtc = [datetime]::UtcNow,
          # an INTERNAL answer on the company's behalf (a Manager Admin or a sponsor-department Owner, checked by the
          # caller -- the escalation mail invites it); recorded as 'internal:<who>'
          [switch]$Internal)
    $no = { param($r) [pscustomobject]@{ ok = $false; reason = $r; campaign = $Campaign } }
    if ("$($Campaign.closedUtc)".Trim()) { return (& $no 'this review is closed') }
    $by = "$By".Trim().ToLowerInvariant()
    if ($Internal) { $by = 'internal:' + $by }
    elseif (@(Get-PimCompanyContacts -Company $Company) -notcontains $by) { return (& $no "$By is not a contact of $($Campaign.company)") }
    $u = "$Upn".Trim().ToLowerInvariant()
    $item = @($Campaign.items | Where-Object { "$($_.upn)" -eq $u }) | Select-Object -First 1
    if (-not $item) { return (& $no "$Upn is not on this company's list") }
    if ("$($item.applied)".Trim()) { return (& $no 'this answer has already been applied -- contact the sponsor department to change it') }
    $until = ''
    if ($Answer -eq 'leave') {
        $d = ConvertFrom-PimCompanyUtc $LeaveUntil
        if (-not $d -or $d -le $NowUtc.ToUniversalTime()) { return (& $no 'on leave needs a return date in the future') }
        $until = $d.ToString('yyyy-MM-dd')
    }
    $c = $Campaign.PSObject.Copy()
    $c.items = @($Campaign.items | ForEach-Object {
        if ("$($_.upn)" -eq $u) { $n = $_.PSObject.Copy(); $n.answer = $Answer; $n.leaveUntil = $until; $n.answeredBy = $by; $n.answeredUtc = $NowUtc.ToUniversalTime().ToString('o'); $n } else { $_ } })
    return [pscustomobject]@{ ok = $true; reason = "$Upn -> $Answer"; campaign = $c }
}

function Get-PimCompanyReviewItemAction {
    <#
      PURE. What the engine does for one answered (or, at day 21, unanswered) item. Returns
      { rowChange = @{ AccountStatus } or $null; raiseRemovalApproval; reason }.
    #>
    param([Parameter(Mandatory)][object]$Item, [switch]$Unanswered)
    if ($Unanswered) { return [pscustomobject]@{ rowChange = [ordered]@{ AccountStatus = 'Disabled' }; raiseRemovalApproval = $false; reason = 'no answer from the company within 21 days -- disabled (re-enable through RFA)' } }
    switch ("$($Item.answer)") {
        'working' { return [pscustomobject]@{ rowChange = $null; raiseRemovalApproval = $false; reason = "confirmed by $($Item.answeredBy)" } }
        'left'    { return [pscustomobject]@{ rowChange = [ordered]@{ AccountStatus = 'Disabled' }; raiseRemovalApproval = $true; reason = "left the company (per $($Item.answeredBy)) -- disabled now; removing the access waits for an internal approver" } }
        'leave'   { return [pscustomobject]@{ rowChange = [ordered]@{ AccountStatus = 'Disabled' }; raiseRemovalApproval = $false; reason = "on leave until $($Item.leaveUntil) (per $($Item.answeredBy)) -- disabled; RFA enables it on return" } }
    }
    return [pscustomobject]@{ rowChange = $null; raiseRemovalApproval = $false; reason = 'no answer yet' }
}
