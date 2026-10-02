#Requires -Version 5.1
<#
  §82 CONSULTANT LIFECYCLE -- the `company-review` job (Pro 'consultants.review'). REQUIREMENTS §82.5-82.8.

  Per company (Account-Definitions-Companies) with consultants and a contact:
    start     a campaign: the consultant list, published to the RFA store for the contacts (PIN sign-in on the portal),
              and a mail to every contact
    answers   taken in from the store (RfaAnswers) -- the ENGINE re-checks each one (Set-PimCompanyReviewAnswer: a listed
              contact, an open campaign, a consultant on the list)
    apply     each answered item once: left -> Disabled now + an offboard APPROVAL request (removal waits for an internal
              approver); leave -> Disabled; working -> nothing
    remind    day 5 / day 10 to the contacts; escalate day 14 to the sponsor department's Owners; day 21 the unanswered
              are Disabled (re-enabled through RFA, never removed)
  The campaign list lives in pim.Settings 'CompanyReviewCampaigns' (CAS, like the access reviews). Disable is
  AccountStatus=Disabled -- NEVER AutoDisableDate (that is offboarding). Mails go out only after the save.
  Without an RFA store the job still runs: answers can then only be recorded in the Manager.
#>

if (-not (Get-Command Get-PimCompanyReviewStep -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-CompanyReview.ps1') }
$__rfa = Join-Path (Split-Path -Parent $PSScriptRoot) 'rfa'
if (-not (Get-Command Get-PimRfaStoreEntities -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $__rfa 'PIM-RfaStore.ps1'))) { . (Join-Path $__rfa 'PIM-RfaStore.ps1') }
if (-not (Get-Command Get-PimRfaDepartmentIndex -ErrorAction SilentlyContinue) -and (Test-Path (Join-Path $__rfa 'PIM-RfaSync.ps1'))) { . (Join-Path $__rfa 'PIM-RfaSync.ps1') }

function Invoke-PimCompanyReviewJob {
    <# Returns { ran; skipped; whatIf; failed; detail }. -Store injects the RFA store (tests). #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [hashtable]$Store, [switch]$NoStore)
    $now = $NowUtc.ToUniversalTime()
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[company-review] no SQL store -- the companies and the admin rows cannot be read' }
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'consultants.review' -Quiet)) {
        return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; failed = $false; detail = 'company-review: the consultant lifecycle is not enabled or not licensed (Pro) -- nothing started' }
    }
    $companies = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Companies')
    if (-not $companies.Count) { return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; failed = $false; detail = 'company-review: no company is defined -- nothing to review' } }
    $admins = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    $deptIdx = Get-PimRfaDepartmentIndex -Departments @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments')
    $settings = Get-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings'
    if (-not $Store -and -not $NoStore) { try { $Store = New-PimRfaStore -Settings $settings } catch { $Store = $null } }
    $portalUrl = "$(if ($settings) { $settings.portalUrl })".Trim()
    $managerUrl = "$(if (Get-Command Resolve-PimManagerMailUrl -ErrorAction SilentlyContinue) { try { Resolve-PimManagerMailUrl } catch { '' } })"
    $log = New-Object System.Collections.Generic.List[string]; $errors = New-Object System.Collections.Generic.List[string]
    $mails = New-Object System.Collections.Generic.List[object]; $rowChanges = New-Object System.Collections.Generic.List[object]; $approvals = New-Object System.Collections.Generic.List[object]
    $enc = { param($x) [System.Net.WebUtility]::HtmlEncode("$x") }

    $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name 'CompanyReviewCampaigns'
    $doc = if ("$raw".Trim()) { $raw | ConvertFrom-Json } else { $null }
    $camps = New-Object System.Collections.Generic.List[object]
    if ($doc -and $doc.PSObject.Properties['campaigns']) { foreach ($c in @($doc.campaigns)) { if ($c) { $camps.Add($c) } } }
    $byUpn = @{}; foreach ($a in $admins) { $u = "$($a.UserPrincipalName)".Trim().ToLowerInvariant(); if ($u) { $byUpn[$u] = $a } }
    $coOf = { param($name) @($companies | Where-Object { "$($_.Company)".Trim().ToLowerInvariant() -eq "$name".Trim().ToLowerInvariant() })[0] }

    # ---- answers from the portal -----------------------------------------------------------------------------
    $taken = @()
    if ($Store) {
        try {
            foreach ($ans in @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaAnswers' -PartitionKey 'ans')) {
                $c = @($camps | Where-Object { "$($_.id)" -eq "$($ans.campaignId)" })[0]
                $co = if ($c) { & $coOf $c.company } else { $null }
                if (-not $c -or -not $co) { $log.Add("answer $($ans.RowKey): no open campaign -- dropped"); $taken += "$($ans.RowKey)"; continue }
                $r = Set-PimCompanyReviewAnswer -Campaign $c -Company $co -Upn "$($ans.upn)" -Answer "$($ans.answer)" -LeaveUntil "$($ans.leaveUntil)" -By "$($ans.by)" -NowUtc $now
                if ($r.ok) { $camps[$camps.IndexOf($c)] = $r.campaign; $log.Add("$($c.company): $($ans.upn) = $($ans.answer) (by $($ans.by))") } else { $log.Add("answer $($ans.RowKey) refused: $($r.reason)") }
                $taken += "$($ans.RowKey)"
            }
        } catch { $errors.Add("the answers could not be read from the RFA store: $($_.Exception.Message)") }
    }

    # ---- steps per company -------------------------------------------------------------------------------------
    foreach ($co in $companies) {
        $name = "$($co.Company)".Trim(); if (-not $name) { continue }
        $mine = @($camps | Where-Object { "$($_.company)".ToLowerInvariant() -eq $name.ToLowerInvariant() })
        $open = @($mine | Where-Object { -not "$($_.closedUtc)".Trim() })[0]
        $lastClosed = @($mine | Where-Object { "$($_.closedUtc)".Trim() } | ForEach-Object { ConvertFrom-PimCompanyUtc $_.closedUtc } | Sort-Object -Descending)[0]
        $consultants = @(Get-PimCompanyConsultants -Company $co -Admins $admins)
        $step = Get-PimCompanyReviewStep -Company $co -Campaign $open -LastClosedUtc $lastClosed -ConsultantCount $consultants.Count -NowUtc $now
        $contacts = @(Get-PimCompanyContacts -Company $co)
        $sponsor = $deptIdx["$($co.SponsorDepartment)".Trim().ToLowerInvariant()]
        switch ($step.action) {
            'start' {
                $c = New-PimCompanyReviewCampaign -Company $co -Admins $admins -NowUtc $now
                $camps.Add($c); $open = $c
                foreach ($to in $contacts) { $mails.Add(@{ to = $to; title = "Please confirm your consultants at $($global:PIM_TenantName)"; headline = "Please confirm which of your people still work for $(& $enc $name)."
                    detail = "$($c.items.Count) person(s) from $(& $enc $name) have an administrator account with us. For each, tell us: still working here, left the company, or on leave until a date."
                    action = 'Open the portal, sign in with the one-time PIN sent to this address, and answer for each person within 14 days.'; url = $portalUrl }) }
                $log.Add("$($name): review started ($($c.items.Count) consultant(s), $($contacts.Count) contact(s))")
            }
            'remind' {
                $open.remindersSent = [int]("0$($open.remindersSent)") + 1
                $n = @($open.items | Where-Object { -not "$($_.answer)".Trim() }).Count
                foreach ($to in $contacts) { $mails.Add(@{ to = $to; title = "Reminder: confirm your consultants"; headline = "$n person(s) from $(& $enc $name) still need your answer."; detail = 'Without an answer the accounts are disabled after 21 days.'; action = 'Open the portal and answer for each person.'; url = $portalUrl }) }
                $log.Add("$($name): reminder $($open.remindersSent)")
            }
            'escalate' {
                $open.escalatedUtc = $now.ToString('o')
                $lines = @($open.items | Where-Object { -not "$($_.answer)".Trim() } | ForEach-Object { '&bull; ' + (& $enc $_.upn) })
                $owners = @(if ($sponsor) { $sponsor.Owners })
                foreach ($o in $owners) { $mails.Add(@{ to = $o; title = "$name has not confirmed its consultants"; headline = "The company review of $(& $enc $name) is unanswered after 14 days."
                    detail = "Your department sponsors these consultants. Without an answer by day 21 they are disabled:<br>" + ($lines -join '<br>'); action = "Contact $(& $enc $name), or confirm on their behalf in the PIM Manager (Companies)."; url = $managerUrl }) }
                if (-not $owners.Count) { $errors.Add("$($name): no Owner in the sponsor department '$($co.SponsorDepartment)' -- the escalation reached nobody") }
                $log.Add("$($name): escalated to $($owners.Count) Owner(s)")
            }
            'disable' {
                foreach ($it in @($open.items | Where-Object { -not "$($_.answer)".Trim() -and -not "$($_.applied)".Trim() })) {
                    $act = Get-PimCompanyReviewItemAction -Item $it -Unanswered
                    $rowChanges.Add(@{ upn = "$($it.upn)"; change = $act.rowChange; reason = $act.reason; item = $it })
                    $it.applied = 'disabled (no answer)'
                }
                $open.closedUtc = $now.ToString('o')
                $log.Add("$($name): day 21 -- unanswered consultants disabled, review closed")
            }
            'close' { $open.closedUtc = $now.ToString('o'); $log.Add("$($name): every consultant answered, review closed") }
        }
        # answered items are applied once, whatever the step
        if ($open) {
            foreach ($it in @($open.items | Where-Object { "$($_.answer)".Trim() -and -not "$($_.applied)".Trim() })) {
                $act = Get-PimCompanyReviewItemAction -Item $it
                if ($act.rowChange) { $rowChanges.Add(@{ upn = "$($it.upn)"; change = $act.rowChange; reason = $act.reason; item = $it }) }
                if ($act.raiseRemovalApproval) { $approvals.Add(@{ upn = "$($it.upn)"; reason = "company review of $($name): $($act.reason)" }) }
                $it.applied = "$($it.answer)"
            }
        }
    }
    if ($WhatIf) { return [pscustomobject]@{ ran = $true; skipped = $false; whatIf = $true; failed = $false; detail = "company-review (WhatIf): $($log -join '; ')" } }

    # ---- save (CAS), then act -----------------------------------------------------------------------------------
    $keep = @($camps | Where-Object { -not "$($_.closedUtc)".Trim() -or ($now - (ConvertFrom-PimCompanyUtc $_.closedUtc)).TotalDays -lt 400 })
    $newJson = ([pscustomobject]@{ campaigns = @($keep) } | ConvertTo-Json -Depth 10 -Compress)
    if ($newJson -ne "$raw") {
        $w = Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name 'CompanyReviewCampaigns' -NewValueJson $newJson -ExpectedValueJson $raw
        if ([int]$w -ne 1) { throw '[company-review] the reviews changed while this run decided (an answer recorded in the Manager) -- nothing applied, the next run retries' }
    }
    $touched = 0
    foreach ($rc in $rowChanges) {
        $a = $byUpn["$($rc.upn)".ToLowerInvariant()]
        if (-not $a) { $errors.Add("$($rc.upn): no admin row -- nothing to disable"); continue }
        if ("$($a.AccountStatus)" -ieq 'Revoked' -or "$($a.AccountStatus)" -ieq "$($rc.change.AccountStatus)") { continue }
        try {
            $row = $a.PSObject.Copy()
            foreach ($k in @($rc.change.Keys)) { $row | Add-Member -NotePropertyName $k -NotePropertyValue $rc.change[$k] -Force }
            # an RFA window is ended too: the company says this person must not work here now
            if ($row.PSObject.Properties['RfaWindowEndUtc']) { $row.RfaWindowEndUtc = '' }
            Set-PimSqlRow -ConnectionString $cs -Entity 'Account-Definitions-Admins' -Key (Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row $row) -Data $row
            $touched++
            if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { try { Write-PimAuditEvent -Action 'company-review.account' -Target "$($rc.upn)" -After $rc.change -Result 'ok' } catch { } }
        } catch { $errors.Add("$($rc.upn): could not be disabled: $($_.Exception.Message)") }
    }
    if ($touched -and (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) { try { [void](Add-PimJobTrigger -Type 'engine-delta' -Scope 'AdminAccounts' -Reason 'company-review') } catch { $errors.Add("engine trigger: $($_.Exception.Message)") } }
    foreach ($ap in $approvals) {
        try {
            $openReq = @(); try { $openReq = @(Get-PimApprovalRequests -Status Pending -Action offboard -Target $ap.upn) } catch { $openReq = @() }
            if ($openReq.Count) { continue }
            if (-not (Get-Command Add-PimApprovalRequest -ErrorAction SilentlyContinue)) { throw 'the approval library is not loaded in this host' }
            [void](Add-PimApprovalRequest -Requestor 'company-review' -Action 'offboard' -Target $ap.upn -Justification $ap.reason)
        } catch { $errors.Add("$($ap.upn): the removal approval could not be raised: $($_.Exception.Message)") }
    }
    foreach ($ml in $mails) {
        if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { break }
        $tok = @{ Title = $ml.title; Headline = $ml.headline; Detail = $ml.detail; Action = $ml.action; PortalUrl = "$($ml.url)"; TenantName = "$($global:PIM_TenantName)"; WhenUtc = $now.ToString('yyyy-MM-dd HH:mm') + ' UTC' }
        try { [void](Send-PimNotifyMail -Type 'rfa-notice' -Tokens $tok -Recipient $ml.to) } catch { $errors.Add("mail to $($ml.to) failed: $($_.Exception.Message)") }
    }
    if ($Store) {
        try {
            foreach ($k in $taken) { Remove-PimRfaStoreEntity -Store $Store -Table 'RfaAnswers' -PartitionKey 'ans' -RowKey $k }
            $salt = "$(if ($settings) { $settings.salt })".Trim()
            $pub = @{}
            foreach ($c in @($keep | Where-Object { -not "$($_.closedUtc)".Trim() })) {
                $co = & $coOf $c.company
                $pub["$($c.id)"] = @{ company = "$($c.company)"; contactKeys = (@(Get-PimCompanyContacts -Company $co | ForEach-Object { Get-PimRfaHash -Salt $salt -Text $_ }) -join '|')
                                      items = (@($c.items | ForEach-Object { [pscustomobject]@{ upn = $_.upn; displayName = $_.displayName; answer = $_.answer; leaveUntil = $_.leaveUntil } }) | ConvertTo-Json -Compress -Depth 4); startedUtc = (Format-PimRfaValue $c.startedUtc) }
            }
            $have = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaReviews' -PartitionKey 'review')
            foreach ($k in @($pub.Keys)) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaReviews' -PartitionKey 'review' -RowKey $k -Entity $pub[$k] }
            foreach ($h in $have) { if (-not $pub.ContainsKey("$($h.RowKey)")) { Remove-PimRfaStoreEntity -Store $Store -Table 'RfaReviews' -PartitionKey 'review' -RowKey "$($h.RowKey)" } }
        } catch { $errors.Add("the RFA store could not be updated: $($_.Exception.Message)") }
    }
    $detail = "company-review: $($companies.Count) compan(ies), $touched account(s) disabled, $($approvals.Count) removal approval(s), $($mails.Count) mail(s)" + $(if ($log.Count) { ' | ' + ($log -join '; ') }) + $(if ($errors.Count) { ' | ERRORS: ' + ($errors -join '; ') })
    return [pscustomobject]@{ ran = $true; skipped = $false; whatIf = $false; failed = [bool]$errors.Count; detail = $detail }
}
