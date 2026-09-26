<#
  PIM-OwnerPortal.ps1 -- §79.8 (and the first slice of §79.7's PIM owner page).

  Operator 2026-09-25: "auto-disable reminder: the dept owner gets a reminder 2 days before a person is auto-disabled; the
  mail link opens the portal, where the owner can extend the auto-disable date". Decision 79.7: "a PIM owner page (per
  department: per person Extend / Keep for another period / Remove), linked from the mail".

  A department owner is named in PIM-Definitions-Departments.Owners. They usually hold NO Manager role (they sign in and
  are a Reader), so this page is scoped by ownership, not by role:
    * they see the people (Account-Definitions-Admins) whose Department they own -- nobody else;
    * they may EXTEND a person's auto-disable date: to a LATER date, in the future, at most -MaxDays from today.
      Never earlier, never today or in the past: a date at or before now disables the account on the next tick -- that is
      an offboard, and an offboard keeps its own approval path (BUG-190). An owner cannot shorten anyone's access here.
  An Admin / SuperAdmin may do the same for anyone (they can already edit the row).

  PURE functions: no SQL, no HTTP. The Manager (Open-PimManager.ps1) reads the rows and writes the one change.
#>
Set-StrictMode -Off

$script:PimOwnerExtendMaxDaysDefault = 365

function Get-PimOwnerIdentityList {
    # "a@x.com; b@x.com, c@x.com | d@x.com" -> lower-case addresses. Anything without an @ is not an owner identity.
    # R25-17: '|' too -- it is the Manager's own multi-value format; such owners got 403 on My people and no owner-review mail.
    param([AllowNull()][string]$Owners)
    return @("$Owners" -split '[|;,\s]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+$' } | Sort-Object -Unique)
}

function Get-PimOwnedDepartments {
    # The departments -Identity owns. -DepartmentOwners: department (any case) -> Owners string.
    param([hashtable]$DepartmentOwners = @{}, [string]$Identity = '')
    $id = "$Identity".Trim().ToLowerInvariant()
    if (-not $id) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($DepartmentOwners.Keys)) {
        if ((Get-PimOwnerIdentityList -Owners "$($DepartmentOwners[$k])") -contains $id) { $out.Add("$k") | Out-Null }
    }
    return @($out.ToArray() | Sort-Object -Unique)
}

function Get-PimOwnerRowValue {
    param([AllowNull()][object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { foreach ($k in @($Row.Keys)) { if ("$k" -ieq $n -and "$($Row[$k])".Trim()) { return $Row[$k] } } }
        else { $p = $Row.PSObject.Properties | Where-Object { "$($_.Name)" -ieq $n } | Select-Object -First 1; if ($p -and "$($p.Value)".Trim()) { return $p.Value } }
    }
    return ''
}

function ConvertTo-PimOwnerDate {
    # A cell value -> UTC [datetime] or $null. [datetime] as is (pwsh 7 hands JSON dates over parsed); text as
    # yyyy-MM-dd[Thh:mm[:ss]][Z] in the invariant culture. A date EXPRESSION (FirstDayNextMonth ...) is resolved by the
    # engine's own resolver when it is loaded, never guessed here.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $fmts = [string[]]@('yyyy-MM-dd', 'yyyy-MM-ddTHH:mm', 'yyyy-MM-ddTHH:mm:ss', 'yyyy-MM-ddTHH:mm:ssZ', 'yyyy-MM-ddTHH:mm:ss.fffffffZ', 'o', 'yyyy-MM-dd HH:mm', 'yyyy-MM-dd HH:mm:ss')
    if ([datetime]::TryParseExact($s, $fmts, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal), [ref]$d)) { return $d }
    if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) {
        try { $r = Resolve-PimDateExpression -Expression $s; if ($r -is [datetime]) { return $r.ToUniversalTime() } } catch { }
    }
    return $null
}

function Get-PimOwnerPeople {
    <#
      The people -Identity may act on: admins whose Department is one they own (or everyone when -All, for an Admin).
      Returns [ { userName; displayName; upn; department; autoDisableDate ('' or yyyy-MM-dd); daysLeft ($null or int);
      accountStatus; canExtend; extendWhy } ], soonest auto-disable first, then by name.
    #>
    param([object[]]$Admins = @(), [hashtable]$DepartmentOwners = @{}, [string]$Identity = '', [switch]$All,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $owned = @(Get-PimOwnedDepartments -DepartmentOwners $DepartmentOwners -Identity $Identity | ForEach-Object { "$_".ToLowerInvariant() })
    $now = $NowUtc.ToUniversalTime()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Admins)) {
        if ($null -eq $r) { continue }
        $dept = "$(Get-PimOwnerRowValue $r @('Department'))".Trim()
        if (-not $All -and -not ($dept -and ($owned -contains $dept.ToLowerInvariant()))) { continue }
        $un = "$(Get-PimOwnerRowValue $r @('UserName'))".Trim()
        $upn = "$(Get-PimOwnerRowValue $r @('UserPrincipalName'))".Trim()
        if (-not $un -and -not $upn) { continue }
        $newRaw = Get-PimOwnerRowValue $r @('AutoDisableDate'); $oldRaw = Get-PimOwnerRowValue $r @('OffboardDate')
        $dRaw = if ("$newRaw".Trim()) { $newRaw } else { $oldRaw }
        $conflict = ("$newRaw".Trim() -and "$oldRaw".Trim() -and ("$newRaw".Trim() -ne "$oldRaw".Trim()))
        $d = if ($conflict) { $null } else { ConvertTo-PimOwnerDate $dRaw }
        $days = if ($d) { [int][math]::Floor(($d - $now).TotalDays) } else { $null }
        $why = ''
        if ($conflict) { $why = 'this person carries two different auto-disable dates -- ask a PIM administrator to correct it' }
        elseif (-not "$dRaw".Trim()) { $why = 'no auto-disable date is set -- there is nothing to extend' }
        elseif (-not $d) { $why = "the auto-disable date '$dRaw' is not a plain date -- ask a PIM administrator" }
        $out.Add([pscustomobject]@{
            userName = $un; upn = $upn; displayName = "$(Get-PimOwnerRowValue $r @('DisplayName'))".Trim(); department = $dept
            autoDisableDate = $(if ($d) { $d.ToString('yyyy-MM-dd') } else { '' }); daysLeft = $days
            accountStatus = "$(Get-PimOwnerRowValue $r @('AccountStatus'))".Trim(); canExtend = (-not $why); extendWhy = $why
        }) | Out-Null
    }
    return @($out.ToArray() | Sort-Object @{ Expression = { if ($null -eq $_.daysLeft) { [int]::MaxValue } else { [int]$_.daysLeft } } }, @{ Expression = { "$($_.displayName)$($_.userName)" } })
}

function Test-PimOwnerExtendRequest {
    <#
      Is "extend this person's auto-disable date to -NewDate" allowed? Returns @{ ok; reason; value (yyyy-MM-dd); before }.
      Allowed only when: the row has a readable auto-disable date; -NewDate is a plain date; it is LATER than that date;
      it is after today; and it is at most -MaxDays from today. Everything else is refused with a reason a business user
      can act on -- never silently clamped.
    #>
    param([Parameter(Mandatory)][AllowNull()][object]$Row, [AllowNull()][string]$NewDate, [int]$MaxDays = 0,
          [datetime]$NowUtc = [datetime]::UtcNow)
    if ($MaxDays -le 0) { $MaxDays = [int]$script:PimOwnerExtendMaxDaysDefault }
    if ($MaxDays -le 0) { $MaxDays = 365 }   # a $script: default can be unset in a child script's scope (the §79.6 trap)
    $no = { param($why) [pscustomobject]@{ ok = $false; reason = $why; value = ''; before = '' } }
    $p = @(Get-PimOwnerPeople -Admins @($Row) -All -NowUtc $NowUtc)
    if (-not $p.Count) { return (& $no 'that person is not a PIM-managed admin') }
    if (-not $p[0].canExtend) { return (& $no $p[0].extendWhy) }
    $s = "$NewDate".Trim()
    if ($s -notmatch '^\d{4}-\d{2}-\d{2}$') { return (& $no "pick a date (yyyy-MM-dd) -- got '$s'") }
    $new = ConvertTo-PimOwnerDate $s
    if (-not $new) { return (& $no "'$s' is not a valid date") }
    $today = $NowUtc.ToUniversalTime().Date
    $cur = ConvertTo-PimOwnerDate $p[0].autoDisableDate
    if ($new -le $today) { return (& $no 'the new date must be after today -- ending access now is an offboard, which a PIM administrator approves') }
    if ($cur -and $new -le $cur) { return (& $no ("the new date must be LATER than the current one ({0}) -- this page only extends access" -f $cur.ToString('yyyy-MM-dd'))) }
    if ($new -gt $today.AddDays($MaxDays)) { return (& $no ("a date more than {0} days ahead ({1}) needs a PIM administrator" -f $MaxDays, $today.AddDays($MaxDays).ToString('yyyy-MM-dd'))) }
    return [pscustomobject]@{ ok = $true; reason = ''; value = $new.ToString('yyyy-MM-dd'); before = $p[0].autoDisableDate }
}

# ======================================================================================================================
# §79.7 THE OWNER REVIEW (operator 2026-09-25: "access review with cadence ... mail to department owners ... the owner can
# (a) extend people, (b) confirm ... for another period, (c) revoke permissions. Business-user friendly"). Decision 79.7:
# on the PIM owner page (My people): per person Extend / Keep / Remove.
#   * Keep   -- the owner confirms the person still needs their access; recorded in pim.Settings['OwnerReviews']
#               (per person: by, utc). A person is DUE when never kept, or last kept longer ago than the cadence.
#   * Remove -- raises an OFFBOARD approval request (the BUG-190 path): a PIM administrator approves and executes it. The
#               owner never disables anyone directly.
#   * The scheduler job 'owner-review' (OFF by default; on/off + cadence on the Jobs page = SuperAdmin) mails each
#     department's owners their people -- due ones first -- with a link to My people.
# ======================================================================================================================

function ConvertTo-PimOwnerReviewMap {
    # pim.Settings['OwnerReviews'] value (JSON text, parsed object or hashtable) -> @{ <username lower> = @{ by; utc } }.
    param([AllowNull()][object]$Value)
    $out = @{}
    if ($null -eq $Value) { return $out }
    $v = $Value
    if ($v -is [string]) { if (-not "$v".Trim()) { return $out }; try { $v = $v | ConvertFrom-Json } catch { return $out } }
    $names = if ($v -is [System.Collections.IDictionary]) { @($v.Keys | ForEach-Object { "$_" }) } else { @($v.PSObject.Properties | ForEach-Object { "$($_.Name)" }) }
    foreach ($n in $names) {
        $k = "$n".Trim().ToLowerInvariant(); if (-not $k) { continue }
        $e = if ($v -is [System.Collections.IDictionary]) { $v[$n] } else { $v.$n }
        $by = "$(Get-PimOwnerRowValue $e @('by'))"; $utc = Get-PimOwnerRowValue $e @('utc')
        $out[$k] = @{ by = $by; utc = $(if ($utc -is [datetime]) { $utc.ToUniversalTime().ToString('o') } else { "$utc" }) }
    }
    return $out
}

function Add-PimOwnerReviewStatus {
    # Annotates people (from Get-PimOwnerPeople) with lastReviewedUtc / reviewedBy / reviewDue. -CadenceDays <= 0 = never due.
    param([object[]]$People = @(), [hashtable]$Reviews = @{}, [int]$CadenceDays = 90, [datetime]$NowUtc = [datetime]::UtcNow)
    foreach ($p in @($People)) {
        if (-not $p) { continue }
        $k = "$(if ("$($p.userName)") { $p.userName } else { $p.upn })".ToLowerInvariant()
        $r = if ($Reviews.ContainsKey($k)) { $Reviews[$k] } else { $null }
        $t = if ($r) { ConvertTo-PimOwnerDate $r.utc } else { $null }
        $due = if ($CadenceDays -le 0) { $false } elseif (-not $t) { $true } else { ($NowUtc.ToUniversalTime() - $t).TotalDays -ge $CadenceDays }
        $p | Add-Member -NotePropertyName lastReviewedUtc -NotePropertyValue $(if ($t) { $t.ToString('yyyy-MM-dd') } else { '' }) -Force
        $p | Add-Member -NotePropertyName reviewedBy -NotePropertyValue $(if ($r) { "$($r.by)" } else { '' }) -Force
        $p | Add-Member -NotePropertyName reviewDue -NotePropertyValue ([bool]$due) -Force
    }
    return @($People)
}

function Get-PimOwnerReviewDigest {
    <#
      PURE. One entry per department that HAS owners and people: @{ department; owners[]; people[] (annotated, due first);
      due }. Departments with people but no owners are returned in .unowned (the job reports them; nobody can be mailed).
    #>
    param([object[]]$Admins = @(), [hashtable]$DepartmentOwners = @{}, [hashtable]$Reviews = @{}, [int]$CadenceDays = 90,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $all = @(Get-PimOwnerPeople -Admins $Admins -All -NowUtc $NowUtc)
    [void](Add-PimOwnerReviewStatus -People $all -Reviews $Reviews -CadenceDays $CadenceDays -NowUtc $NowUtc)
    $ownersLc = @{}; foreach ($k in @($DepartmentOwners.Keys)) { $ownersLc["$k".ToLowerInvariant()] = @(Get-PimOwnerIdentityList -Owners "$($DepartmentOwners[$k])") }
    $out = New-Object System.Collections.Generic.List[object]; $unowned = New-Object System.Collections.Generic.List[string]
    foreach ($g in @($all | Where-Object { "$($_.department)".Trim() } | Group-Object { "$($_.department)".Trim().ToLowerInvariant() })) {
        $own = if ($ownersLc.ContainsKey($g.Name)) { @($ownersLc[$g.Name]) } else { @() }
        $dept = "$($g.Group[0].department)"
        if (-not $own.Count) { $unowned.Add($dept) | Out-Null; continue }
        $ppl = @($g.Group | Sort-Object @{ Expression = { -not $_.reviewDue } }, @{ Expression = { "$($_.displayName)$($_.userName)" } })
        $out.Add([pscustomobject]@{ department = $dept; owners = @($own); people = $ppl; due = @($ppl | Where-Object { $_.reviewDue }).Count }) | Out-Null
    }
    return [pscustomobject]@{ departments = @($out.ToArray()); unowned = @($unowned.ToArray() | Sort-Object -Unique) }
}

function Invoke-PimOwnerReviewJob {
    <#
      The 'owner-review' job. Reads the admins, the departments and the recorded reviews from SQL, and mails each
      department's owners their people (due first) with a link to My people. Mail hold states (kill switch, feature off,
      allowlist, no sender) are SKIPS, not failures. Changes nothing in the store.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[owner-review] no SQL store -- the admins and departments cannot be read' }
    $admins = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    $idx = @{}
    foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments')) {
        $n = "$(Get-PimOwnerRowValue $r @('Department','DepartmentName','Name'))".Trim(); if (-not $n) { continue }
        $idx[$n.ToLowerInvariant()] = "$(Get-PimOwnerRowValue $r @('Owners','DeptOwner','DepartmentOwner','ManagerEmail'))"
    }
    $rev = ConvertTo-PimOwnerReviewMap (Get-PimSqlSetting -ConnectionString $cs -Name 'OwnerReviews')
    $cad = 90; if ($Job -and $Job.PSObject.Properties['intervalMinutes'] -and [int]$Job.intervalMinutes -gt 0) { $cad = [int][math]::Max(1, [math]::Round([int]$Job.intervalMinutes / 1440)) }
    $dg = Get-PimOwnerReviewDigest -Admins $admins -DepartmentOwners $idx -Reviews $rev -CadenceDays $cad -NowUtc $NowUtc
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $sent = 0; $held = 0; $failed = 0
    foreach ($d in @($dg.departments)) {
        $lines = @($d.people | Select-Object -First 25 | ForEach-Object {
            '&bull; <b>' + (& $enc $(if ($_.displayName) { $_.displayName } else { $_.userName })) + '</b>' +
            $(if ($_.autoDisableDate) { ' -- access ends ' + $_.autoDisableDate } else { '' }) +
            $(if ($_.reviewDue) { $(if ($_.lastReviewedUtc) { ' -- last confirmed ' + $_.lastReviewedUtc } else { ' -- not yet confirmed' }) } else { ' -- confirmed ' + $_.lastReviewedUtc }) })
        $tokens = @{
            AlertTitle  = ("Please review who in {0} has privileged access ({1} to confirm)" -f $d.department, $d.due)
            AlertEvent  = 'owner-review'
            AlertDetail = ("You are an owner of <b>{0}</b>. These people have privileged access through PIM. Open the link and, for each person: <b>Keep</b> if they still need it, <b>Extend</b> if their access should last longer, or <b>Remove</b> if they no longer need it (a PIM administrator then approves the removal).<br><br>{1}" -f (& $enc $d.department), ($lines -join '<br>'))
            PortalTab   = 'owner'
            TenantName  = "$($global:PIM_TenantName)"; Instance = 'scheduler'; WhenUtc = $NowUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        }
        foreach ($o in @($d.owners)) {
            $ok = $false; $why = ''
            try {
                $m = Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $o -WhatIf:$WhatIf
                if ($m -is [hashtable]) { $ok = [bool]$m['sent']; $why = "$($m['reason'])" } elseif ($m) { $ok = [bool]$m.sent; $why = "$($m.reason)" }
            } catch { $why = "$($_.Exception.Message)" }
            if ($ok -or $WhatIf) { $sent++ }
            elseif ((Get-Command Test-PimMailHoldReason -ErrorAction SilentlyContinue) -and (Test-PimMailHoldReason -Reason $why)) { $held++ }
            else { $failed++; Write-Warning "[owner-review] $($d.department) -> $o not sent: $why" }
        }
    }
    $nd = @($dg.departments).Count
    $detail = ("owner-review: {0} department(s), {1} owner mail(s) sent, {2} held (mail off), {3} failed; cadence {4} day(s){5}" -f $nd, $sent, $held, $failed, $cad,
               $(if (@($dg.unowned).Count) { '; departments with people but NO owners (nobody to ask): ' + (@($dg.unowned) -join ', ') } else { '' }))
    [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; failed = [bool]($failed -gt 0); detail = $detail }
}
