#Requires -Version 5.1
<#
  §82 RFA -- the ENGINE side: the `rfa-sync` job (Pro 'rfa.portal'). REQUIREMENTS §82.6-82.8.

  Every minute, inside the PIM environment, with the engine's managed identity:
    1. publish what the portal needs: the salt and the ELIGIBILITY list (salted UPN hash -> PIN address, mode, durations)
    2. take in what the portal / the API submitted (RfaRequests state 'submitted' / 'cancel-requested'); the ENGINE
       re-decides everything with the pure core -- nothing the public side says is trusted
    3. step every request (expire / enable / warn / end / cancel) -- decisions only, in memory
    4. save the request list (pim.Settings 'RfaRequests') with compare-and-swap; a lost race throws, the next run retries
    5. make the admin rows MATCH the saved state (self-healing): an account with an active window is Enabled with the
       latest end; an account whose RFA window is over is Disabled -- 🔒 ONLY an account RFA enabled itself
       (RfaWindowEndUtc set). Never AutoDisableDate (offboarding). Group requests (API only) become an Active
       PIM-Assignments-Admins row tagged with the request id, and Action=Remove at the end.
    6. mail, ONLY after the save (no duplicate mail on a retried run), then push each request's status to the store.
#>

if (-not (Get-Command Get-PimRfaEffectiveMode -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-Rfa.ps1') }
if (-not (Get-Command Get-PimRfaStoreEntities -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-RfaStore.ps1') }
if (-not (Get-Command Test-PimApiKeyRecord -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-RfaBroker.ps1') }   # §90 API keys

$script:PimRfaTerminalStates = @('denied', 'expired', 'ended', 'cancelled', 'rejected', 'failed')
$script:PimRfaKeepDays = 90

function Get-PimRfaDepartmentIndex {
    <#
      PURE. Department name (lower-case) -> merged @{ Department; Owners[]; RfaMode; RfaDurations }. One department can
      have several rows (its owner row + DEPT- group rows): Owners are united, RfaMode / RfaDurations come from the first
      row that sets them (an owner row -- no GroupTag -- is read first).
    #>
    param([object[]]$Departments = @())
    $idx = @{}
    $rows = @(@($Departments | Where-Object { -not "$($_.GroupTag)".Trim() }) + @($Departments | Where-Object { "$($_.GroupTag)".Trim() }))
    foreach ($d in $rows) {
        $name = "$(if ("$($d.Department)".Trim()) { $d.Department } else { $d.DepartmentName })".Trim()
        if (-not $name) { continue }
        $k = $name.ToLowerInvariant()
        if (-not $idx.ContainsKey($k)) { $idx[$k] = [pscustomobject]@{ Department = $name; Owners = @(); RfaMode = ''; RfaDurations = '' } }
        $e = $idx[$k]
        $e.Owners = @(@($e.Owners) + @("$($d.Owners)" -split '[|,;\s]+' | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ }) | Select-Object -Unique)
        if (-not $e.RfaMode -and "$($d.RfaMode)".Trim()) { $e.RfaMode = "$($d.RfaMode)".Trim() }
        if (-not $e.RfaDurations -and "$($d.RfaDurations)".Trim()) { $e.RfaDurations = "$($d.RfaDurations)".Trim() }
    }
    return $idx
}

function Get-PimRfaAdminRowPlan {
    <#
      PURE. Step 5 for ENABLE requests: the AccountStatus / RfaWindowEndUtc each admin row should carry. Returns a list
      of @{ upn; change = @{ AccountStatus; RfaWindowEndUtc } } for rows that DIFFER.
        * an active enable window -> Enabled, RfaWindowEndUtc = the LATEST active end
        * no active window, but the row carries RfaWindowEndUtc (RFA enabled it) -> Disabled, RfaWindowEndUtc cleared
        * a row RFA never touched (no RfaWindowEndUtc, no active window) is never changed
    #>
    param([object[]]$Requests = @(), [object[]]$Admins = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $activeEnd = @{}
    foreach ($r in @($Requests | Where-Object { "$($_.kind)" -eq 'enable' -and "$($_.state)" -eq 'active' })) {
        $end = ConvertFrom-PimRfaUtc $r.windowEndUtc
        if (-not $end -or $end -le $now) { continue }
        $u = "$($r.upn)".ToLowerInvariant()
        if (-not $activeEnd.ContainsKey($u) -or $end -gt $activeEnd[$u]) { $activeEnd[$u] = $end }
    }
    $out = @()
    foreach ($a in @($Admins)) {
        $u = (Get-PimRfaRowValue -Row $a -Name 'UserPrincipalName').ToLowerInvariant()
        if (-not $u) { continue }
        $st = Get-PimRfaRowValue -Row $a -Name 'AccountStatus'; $we = Get-PimRfaRowValue -Row $a -Name 'RfaWindowEndUtc'
        if ($activeEnd.ContainsKey($u)) {
            $want = $activeEnd[$u].ToString('yyyy-MM-ddTHH:mm:ssZ')
            if ($st -ine 'Enabled' -or $we -ne $want) { $out += [pscustomobject]@{ upn = $u; change = [ordered]@{ AccountStatus = 'Enabled'; RfaWindowEndUtc = $want } } }
        } elseif ($we) {
            if ($st -ieq 'Revoked') { $out += [pscustomobject]@{ upn = $u; change = [ordered]@{ AccountStatus = 'Revoked'; RfaWindowEndUtc = '' } }; continue }
            $out += [pscustomobject]@{ upn = $u; change = [ordered]@{ AccountStatus = 'Disabled'; RfaWindowEndUtc = '' } }
        }
    }
    return @($out)
}

function Get-PimRfaGroupRowPlan {
    <#
      PURE. Step 5 for GROUP requests (API only): the PIM-Assignments-Admins rows. Returns @{ key; row } per row to write.
        * an active group request -> an Active, non-extending membership row tagged RfaRequestId, Action=Assign
        * a request no longer active whose row (tagged with ITS id) is still Assign -> Action=Remove
        * a row NOT tagged with an RFA request id is never touched (the request was refused at intake for that reason)
    #>
    param([object[]]$Requests = @(), [object[]]$Assignments = @(), [object[]]$Admins = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $userOf = @{}; foreach ($a in @($Admins)) { $u = (Get-PimRfaRowValue -Row $a -Name 'UserPrincipalName').ToLowerInvariant(); if ($u) { $userOf[$u] = (Get-PimRfaRowValue -Row $a -Name 'UserName') } }
    $rowOf = @{}; foreach ($r in @($Assignments)) { $rowOf[("$($r.Username)|$($r.GroupTag)").ToLowerInvariant()] = $r }
    $out = @()
    foreach ($q in @($Requests | Where-Object { "$($_.kind)" -eq 'group' })) {
        $user = $userOf["$($q.upn)".ToLowerInvariant()]
        if (-not $user) { continue }
        $key = "$user|$($q.groupName)"; $cur = $rowOf[$key.ToLowerInvariant()]
        $active = ("$($q.state)" -eq 'active' -and (ConvertFrom-PimRfaUtc $q.windowEndUtc) -gt $now)
        if ($active) {
            $days = [int][Math]::Max(1, [Math]::Ceiling([int]$q.hours / 24.0))
            if ($cur -and "$($cur.RfaRequestId)" -eq "$($q.id)" -and "$($cur.Action)" -ne 'Remove') { continue }
            $out += [pscustomobject]@{ key = $key; row = [pscustomobject][ordered]@{ Username = $user; GroupTag = "$($q.groupName)"; AssignmentType = 'Active'; Action = 'Assign'; UpdateExisting = 'TRUE'
                                                                                    AutoExtend = 'FALSE'; NumOfDaysWhenExpire = "$days"; Permanent = 'FALSE'; RfaRequestId = "$($q.id)" } }
        } elseif ($cur -and "$($cur.RfaRequestId)" -eq "$($q.id)" -and "$($cur.Action)" -ne 'Remove') {
            $n = $cur.PSObject.Copy(); $n.Action = 'Remove'
            $out += [pscustomobject]@{ key = $key; row = $n }
        }
    }
    return @($out)
}

function Read-PimRfaMirror {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name 'RfaRequests'
    $doc = if ("$raw".Trim()) { $raw | ConvertFrom-Json } else { $null }
    $list = New-Object System.Collections.Generic.List[object]
    if ($doc -and $doc.PSObject.Properties['requests']) { foreach ($r in @($doc.requests)) { if ($r) { $list.Add($r) } } }
    return [pscustomobject]@{ raw = $raw; requests = $list }
}

function Invoke-PimRfaSyncJob {
    <# The job. Returns { ran; skipped; whatIf; detail; failed }. -Store injects a store (tests). #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [hashtable]$Store)
    $now = $NowUtc.ToUniversalTime()
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[rfa-sync] no SQL store -- the admin rows and the requests cannot be read' }
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'rfa.portal' -Quiet)) {
        return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; failed = $false; detail = 'rfa-sync: the RFA portal is not enabled or not licensed (Pro) -- nothing to do' }
    }
    $settings = Get-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings'
    if (-not $Store) { $Store = New-PimRfaStore -Settings $settings }
    if (-not $Store) { return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; failed = $false; detail = 'rfa-sync: no RFA store configured (RfaSettings.storeAccount) -- deploy the RFA portal first' } }
    $log = New-Object System.Collections.Generic.List[string]; $errors = New-Object System.Collections.Generic.List[string]
    $mails = New-Object System.Collections.Generic.List[object]

    # ---- inputs -----------------------------------------------------------------------------------------------
    $admins = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    $deptIdx = Get-PimRfaDepartmentIndex -Departments @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments')
    $companies = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Companies')
    $assign = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Assignments-Admins')
    # §91.7: the defined groups, read only when ad-hoc groups are offered (RfaSettings.adHocGroups)
    $defs = @()
    if ($settings -and $settings.PSObject.Properties['adHocGroups'] -and @(@($settings.adHocGroups) | Where-Object { "$_".Trim() }).Count) {
        foreach ($de in 'PIM-Definitions-Roles', 'PIM-Definitions-Organization', 'PIM-Definitions-Departments', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg', 'PIM-Definitions-Processes', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services') {
            try { $defs += @(Get-PimSqlRows -ConnectionString $cs -Entity $de) } catch { }
        }
    }
    $salt = "$(if ($settings) { $settings.salt })".Trim()
    if (-not $salt) {
        $b = New-Object byte[] 16; $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); try { $rng.GetBytes($b) } finally { $rng.Dispose() }
        $salt = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
        $s2 = if ($settings) { $settings.PSObject.Copy() } else { [pscustomobject]@{} }
        $s2 | Add-Member -NotePropertyName salt -NotePropertyValue $salt -Force
        if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings' -Value $s2 }
        $settings = $s2; $log.Add('salt created')
    }
    $byUpn = @{}; $byKey = @{}
    foreach ($a in $admins) { $u = (Get-PimRfaRowValue -Row $a -Name 'UserPrincipalName').ToLowerInvariant(); if ($u) { $byUpn[$u] = $a; $byKey[(Get-PimRfaAccountKey -Salt $salt -UserPrincipalName $u)] = $a } }
    $deptOf = { param($a) $deptIdx[(Get-PimRfaRowValue -Row $a -Name 'Department').ToLowerInvariant()] }
    $apiApps = @(@(if ($settings -and $settings.PSObject.Properties['apiAppIds']) { $settings.apiAppIds }) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    # §90: the API keys the Manager issued (hash only), pim.Settings 'ApiKeys' = { keys: [...] }
    $apiKeys = @()
    try { $ak = Get-PimSqlSetting -ConnectionString $cs -Name 'ApiKeys'; if ($ak -and $ak.PSObject.Properties['keys']) { $apiKeys = @($ak.keys) } } catch { $apiKeys = @() }
    $portalUrl = "$(if ($settings) { $settings.portalUrl })".Trim()
    $managerUrl = "$(if (Get-Command Resolve-PimManagerMailUrl -ErrorAction SilentlyContinue) { try { Resolve-PimManagerMailUrl } catch { '' } })"
    $storeRows = @{}; foreach ($r in @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaRequests' -PartitionKey 'req')) { $storeRows["$($r.RowKey)"] = $r }

    # ---- 2 + 3: intake and steps, in memory -------------------------------------------------------------------
    $m = Read-PimRfaMirror -ConnectionString $cs
    $reqs = $m.requests
    # a request may be named by SEVERAL store rows (the same ticket submitted twice): storeIds holds them all
    $find = { param($id) @($reqs | Where-Object { "$($_.id)" -eq "$id" -or @($_.storeIds) -contains "$id" })[0] }
    $note = { param($r, $text) $r | Add-Member -NotePropertyName note -NotePropertyValue $text -Force }
    $reject = @{}
    $forward = @{}   # REQ 90: store row id -> the status text of a proposal handed to the intake
    foreach ($sr in @($storeRows.Values | Where-Object { "$($_.state)" -eq 'submitted' })) {
        $sid = "$($sr.RowKey)"
        if (& $find $sid) { continue }   # already taken in (the status push below brings the store row up to date)
        $src = "$($sr.source)"
        $admin = $null
        if ($src -eq 'portal') { $admin = $byKey["$($sr.accountKey)"] }
        elseif ($src -eq 'api') {
            # §90: the API is its own Pro feature (api.broker)
            if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'api.broker' -Quiet)) { $reject[$sid] = 'the access request API is not enabled here (Pro feature api.broker)'; continue }
            # §90: an allow-listed Entra application OR a valid PIM API key with requests.write (re-checked HERE -- the
            # broker's own check is only the fast answer)
            $kid = "$($sr.callerKeyId)".Trim()
            if ($kid) {
                $kr = @($apiKeys | Where-Object { "$($_.id)" -eq $kid })[0]
                $kv = Test-PimApiKeyRecord -Record $kr -Scope 'requests.write' -NowUtc $now
                if (-not $kv.ok) { $reject[$sid] = "API key: $($kv.reason)"; continue }
            } elseif ($apiApps -notcontains "$($sr.callerAppId)".Trim().ToLowerInvariant()) { $reject[$sid] = 'the calling application is not allowed to use the RFA API'; continue }
            $admin = $byUpn["$($sr.upn)".Trim().ToLowerInvariant()]
        } else { $reject[$sid] = "unknown source '$src'"; continue }
        if (-not $admin) { $reject[$sid] = 'no such account here'; continue }
        # REQ 90: a PROPOSAL (a standing change) goes to the existing intake -- its gates (no activation, no self-targeting,
        # Tier 0/1 always to a human) and the servicenow-intake job turn it into a PENDING change for an administrator to
        # review and commit. It never becomes an RFA window and is never applied by the machine.
        if ($src -eq 'api' -and "$($sr.kind)" -eq 'proposal') {
            $intakeOn = $false; if (Get-Command Test-PimIntakeConfigured -ErrorAction SilentlyContinue) { try { $intakeOn = [bool](Test-PimIntakeConfigured) } catch { $intakeOn = $false } }
            if (-not $intakeOn) { $reject[$sid] = 'proposals are not accepted here -- the intake (IntakeEnabled) is switched off'; continue }
            $rec = [ordered]@{ externalId = "$($sr.externalRef)"; requestType = "$($sr.requestType)"; requestor = "$($sr.requestor)"; targetAdmin = (Get-PimRfaRowValue -Row $admin -Name 'UserName')
                               groupTag = "$($sr.groupName)"; justification = "$($sr.reason)"; source = "api:$(if ("$($sr.callerKeyId)".Trim()) { "key:$($sr.callerKeyId)" } else { "app:$($sr.callerAppId)" })" }
            $gate = Test-PimIntakeAccepted -Record ([pscustomobject]$rec)
            if (-not $gate.accepted) { $reject[$sid] = "proposal refused: $($gate.reason)"; continue }
            if (-not $WhatIf) {
                try { [void](Add-PimIntakeRecord -Record ([pscustomobject]$rec)) } catch { $errors.Add("$sid : the proposal could not be handed to the intake: $($_.Exception.Message)"); continue }
            }
            $forward[$sid] = "Proposal forwarded -- it becomes a pending change that an administrator reviews and commits in PIM (ticket $($sr.externalRef))."
            $log.Add("$sid proposal forwarded to the intake: $($rec.requestType) $($rec.targetAdmin) -> $($rec.groupTag)")
            continue
        }
        $hours = 0; [void][int]::TryParse("$($sr.hours)", [ref]$hours)
        $isC = Test-PimRfaIsConsultant -Admin $admin -Companies $companies
        $kind = if ("$($sr.kind)" -eq 'group') { 'group' } else { 'enable' }
        if ($kind -eq 'group') {
            $un = Get-PimRfaRowValue -Row $admin -Name 'UserName'
            $clash = @($assign | Where-Object { "$($_.Username)" -ieq $un -and "$($_.GroupTag)" -ieq "$($sr.groupName)" -and -not "$($_.RfaRequestId)".Trim() })
            if ($clash.Count) { $reject[$sid] = "the account already has a managed assignment to $($sr.groupName) -- RFA does not change it"; continue }
        }
        $nr = if ($src -eq 'portal' -and $kind -eq 'group') {
                  # §91.7: ad-hoc access to a permission group -- re-checked HERE against the CURRENT list (the broker's check is only the fast answer)
                  New-PimRfaRequest -Admin $admin -Department (& $deptOf $admin) -Hours $hours -Source portal -Kind group -GroupName "$($sr.groupName)" -Reason "$($sr.reason)" -NowUtc $now -IsConsultant:$isC -Id $sid `
                      -RequestableGroups @(Get-PimRfaRequestableGroups -Settings $settings -Admin $admin -Assignments $assign -Definitions $defs) -GroupHours @(Get-PimRfaAdHocHours -Settings $settings -Department (& $deptOf $admin)) }
              elseif ($src -eq 'portal') { New-PimRfaRequest -Admin $admin -Department (& $deptOf $admin) -Hours $hours -Source portal -Reason "$($sr.reason)" -NowUtc $now -IsConsultant:$isC -Id $sid }
              else { New-PimRfaRequest -Admin $admin -Department (& $deptOf $admin) -Hours $hours -Source api -Kind $kind -GroupName "$($sr.groupName)" -ExternalRef "$($sr.externalRef)" -RequestedBy "api:$($sr.callerAppId)" -Reason "$($sr.reason)" -NowUtc $now -IsConsultant:$isC }
        if (-not $nr.ok) { $reject[$sid] = $nr.reason; continue }
        $existing = & $find $nr.request.id
        if ($existing) { $existing | Add-Member -NotePropertyName storeIds -NotePropertyValue @(@($existing.storeIds) + $sid | Where-Object { $_ } | Select-Object -Unique) -Force; $log.Add("$sid = $($existing.id) (same ticket, idempotent)"); continue }
        $nr.request | Add-Member -NotePropertyName storeIds -NotePropertyValue @($sid) -Force
        $reqs.Add($nr.request)
        $log.Add("$sid taken in: $($nr.request.upn) $($nr.request.kind) $($nr.request.hours) h -> $($nr.request.state)")
        if ($nr.request.state -eq 'pending-approval') {
            $d = & $deptOf $admin
            foreach ($o in @(if ($d) { $d.Owners })) {
                $mails.Add(@{ to = $o; title = "Access request from $($nr.request.upn)"; headline = $(if ($nr.request.kind -eq 'group') { "Someone asks for AD-HOC membership of $($nr.request.groupName) (removed automatically when the time is up)." } else { 'Someone asks to have their admin account enabled.' })
                              detail = "<b>$([System.Net.WebUtility]::HtmlEncode($nr.request.upn))</b> asks for $($nr.request.hours) hours$(if ($nr.request.company) { " (consultant from $([System.Net.WebUtility]::HtmlEncode($nr.request.company)))" }). Reason: $([System.Net.WebUtility]::HtmlEncode($(if ($nr.request.reason) { $nr.request.reason } else { '(none given)' })))."
                              action = 'Open Access requests in the PIM Manager and approve or deny it within 24 hours.'; url = $managerUrl })
            }
            if (-not @(if ($d) { $d.Owners }).Count) { $errors.Add("$($nr.request.upn): the department has no Owner -- nobody can approve the request") }
        }
    }
    foreach ($sr in @($storeRows.Values | Where-Object { "$($_.state)" -eq 'cancel-requested' })) {
        $r = & $find "$($sr.RowKey)"
        if ($r -and "$($r.state)" -in @('pending-approval', 'approved', 'active')) { $r.state = 'cancel-requested'; $log.Add("$($r.id): cancel requested") }
    }
    $ctx = { param($r) $byUpn["$($r.upn)".ToLowerInvariant()] }
    $mailUser = { param($r, $title, $headline, $detail, $action)
        $a = & $ctx $r; $to = Get-PimRfaRowValue -Row $a -Name 'ContactEmail'
        if ($to) { $mails.Add(@{ to = $to; title = $title; headline = $headline; detail = $detail; action = $action; url = $portalUrl }) } }
    foreach ($r in $reqs.ToArray()) {
        if ("$($r.state)" -in $script:PimRfaTerminalStates) { continue }
        $step = Get-PimRfaRequestStep -Request $r -NowUtc $now
        if ($step.action -eq 'none') { continue }
        $n = Invoke-PimRfaRequestStep -Request $r -Action $step.action -NowUtc $now
        $i = $reqs.IndexOf($r); $reqs[$i] = $n
        $end = ConvertFrom-PimRfaUtc $n.windowEndUtc
        $endTxt = if ($end) { $end.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { '' }
        switch ($step.action) {
            'expire' { & $mailUser $n 'Your access request expired' 'Nobody decided your request within 24 hours.' 'The request has expired and your account stays disabled.' 'Send a new request in the portal if you still need access.' }
            'enable' {
                $what = if ($n.kind -eq 'group') { "membership of $($n.groupName)" } else { 'your admin account' }
                & $mailUser $n 'Your access is enabled' "$what is enabled until $endTxt." "The request was approved ($(if ($n.decidedBy -eq 'auto') { 'automatically' } else { "by $($n.decidedBy)" }))." 'Sign in with your admin account and activate your roles with MFA (PIM Activator or the Azure portal). The account is disabled again when the time is up.'
                if ($n.decidedBy -eq 'auto') {
                    $d = & $deptOf (& $ctx $n)
                    foreach ($o in @(if ($d) { $d.Owners })) { $mails.Add(@{ to = $o; title = "Admin account enabled: $($n.upn)"; headline = 'An account was enabled automatically.'; detail = "$([System.Net.WebUtility]::HtmlEncode($n.upn)) enabled their admin account until $endTxt (auto-approved by the department's RFA rule)."; action = 'Nothing, unless you did not expect it -- then end it on Access requests in the PIM Manager.'; url = $managerUrl }) }
                }
            }
            'warn-ending' { & $mailUser $n 'Your access ends within the hour' "Your access ends at $endTxt." 'After that the account is disabled again.' 'If you need more time, send a new request in the portal now.' }
            'end'         { & $mailUser $n 'Your access has ended' 'The time you requested is up.' 'Your admin account is disabled again (your roles are kept for the next time).' 'Send a new request in the portal the next time you need it.' }
            'cancel'      { & $mailUser $n 'Your access was ended early' 'Your request was cancelled.' 'Your admin account is disabled again.' 'Send a new request in the portal if you still need access.' }
        }
        $log.Add("$($n.id) $($n.upn): $($step.action)")
    }
    foreach ($r in @($reqs | Where-Object { "$($_.state)" -eq 'denied' -and -not "$($_.notifiedUtc)".Trim() })) {
        & $mailUser $r 'Your access request was denied' 'Your request was not approved.' $(if ("$($r.note)".Trim()) { "Note from $($r.decidedBy): $([System.Net.WebUtility]::HtmlEncode($r.note))" } else { "Denied by $($r.decidedBy)." }) 'Contact your sponsor department if you think this is wrong.'
        $r | Add-Member -NotePropertyName notifiedUtc -NotePropertyValue $now.ToString('o') -Force
    }
    # keep 90 days of finished requests
    $keep = @($reqs | Where-Object { "$($_.state)" -notin $script:PimRfaTerminalStates -or -not (ConvertFrom-PimRfaUtc $(if ("$($_.endedUtc)".Trim()) { $_.endedUtc } elseif ("$($_.decidedUtc)".Trim()) { $_.decidedUtc } else { $_.requestedUtc })) -or ($now - (ConvertFrom-PimRfaUtc $(if ("$($_.endedUtc)".Trim()) { $_.endedUtc } elseif ("$($_.decidedUtc)".Trim()) { $_.decidedUtc } else { $_.requestedUtc }))).TotalDays -lt $script:PimRfaKeepDays })

    if ($WhatIf) { return [pscustomobject]@{ ran = $true; skipped = $false; whatIf = $true; failed = $false; detail = "rfa-sync (WhatIf): $($log -join '; ')" } }

    # ---- 4: save (CAS) ----------------------------------------------------------------------------------------
    $newJson = ([pscustomobject]@{ requests = @($keep) } | ConvertTo-Json -Depth 8 -Compress)
    if ($newJson -ne "$($m.raw)") {
        $w = Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name 'RfaRequests' -NewValueJson $newJson -ExpectedValueJson $m.raw
        if ([int]$w -ne 1) { throw '[rfa-sync] the request list changed while this run decided (a decision in the Manager) -- nothing applied, the next run retries' }
    }

    # ---- 5: make the rows match (self-healing) ----------------------------------------------------------------
    $touchedAdmins = 0; $touchedGroups = 0
    foreach ($p in @(Get-PimRfaAdminRowPlan -Requests $keep -Admins $admins -NowUtc $now)) {
        try {
            $row = $byUpn[$p.upn].PSObject.Copy()
            foreach ($k in @($p.change.Keys)) { $row | Add-Member -NotePropertyName $k -NotePropertyValue $p.change[$k] -Force }
            $key = Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row $row
            if (-not $key) { throw 'the admin row has no UserName (no store key)' }
            Set-PimSqlRow -ConnectionString $cs -Entity 'Account-Definitions-Admins' -Key $key -Data $row
            $touchedAdmins++
            if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { try { Write-PimAuditEvent -Action 'rfa.account' -Target $p.upn -After $p.change -Result 'ok' } catch { } }
        } catch { $errors.Add("$($p.upn): the admin row could not be updated: $($_.Exception.Message)") }
    }
    foreach ($g in @(Get-PimRfaGroupRowPlan -Requests $keep -Assignments $assign -Admins $admins -NowUtc $now)) {
        try {
            Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Assignments-Admins' -Key $g.key -Data $g.row
            $touchedGroups++
            if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { try { Write-PimAuditEvent -Action 'rfa.group' -Target $g.key -After $g.row -Result 'ok' } catch { } }
        } catch { $errors.Add("$($g.key): the membership row could not be written: $($_.Exception.Message)") }
    }
    if ($touchedAdmins -and (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) { try { [void](Add-PimJobTrigger -Type 'engine-delta' -Scope 'AdminAccounts' -Reason 'rfa-sync') } catch { $errors.Add("engine trigger (AdminAccounts): $($_.Exception.Message)") } }
    if ($touchedGroups -and (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) { try { [void](Add-PimJobTrigger -Type 'engine-delta' -Scope 'AdminMembers' -Reason 'rfa-sync') } catch { $errors.Add("engine trigger (AdminMembers): $($_.Exception.Message)") } }

    # ---- 6: mail, then publish ----------------------------------------------------------------------------------
    foreach ($ml in $mails) {
        if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { break }
        $tok = @{ Title = $ml.title; Headline = $ml.headline; Detail = $ml.detail; Action = $ml.action; PortalUrl = "$($ml.url)"; TenantName = "$($global:PIM_TenantName)"; WhenUtc = $now.ToString('yyyy-MM-dd HH:mm') + ' UTC' }
        try { $res = Send-PimNotifyMail -Type 'rfa-notice' -Tokens $tok -Recipient $ml.to; if ($res -and $res.PSObject.Properties['sent'] -and -not $res.sent -and "$($res.reason)" -notmatch '(?i)whatif|held') { $errors.Add("mail to $($ml.to) not sent: $($res.reason)") } }
        catch { $errors.Add("mail to $($ml.to) failed: $($_.Exception.Message)") }
    }
    try {
        $cfg = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaConfig' -PartitionKey 'config' | Where-Object { "$($_.RowKey)" -eq 'salt' })[0]
        if (-not $cfg -or "$($cfg.value)" -ne $salt) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaConfig' -PartitionKey 'config' -RowKey 'salt' -Entity @{ value = $salt } }
        # §90: what the broker needs for a fast API answer (the engine re-checks every request): the allowed apps + the
        # valid API keys (hash only)
        $appsCsv = (@($apiApps) -join ',')
        $cfgS = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaConfig' -PartitionKey 'config' | Where-Object { "$($_.RowKey)" -eq 'settings' })[0]
        if (-not $cfgS -or "$($cfgS.apiAppIds)" -ne $appsCsv) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaConfig' -PartitionKey 'config' -RowKey 'settings' -Entity @{ apiAppIds = $appsCsv } }
        if (Get-Command Get-PimApiKeyPublishRows -ErrorAction SilentlyContinue) {
            $wantK = @{}; foreach ($k in @(Get-PimApiKeyPublishRows -Keys $apiKeys -NowUtc $now)) { $wantK["$($k.hash)"] = $k }
            $haveK = @{}; foreach ($k in @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaApiKeys' -PartitionKey 'key')) { $haveK["$($k.RowKey)"] = $k }
            foreach ($h in @($wantK.Keys)) { $w = $wantK[$h]; $x = $haveK[$h]; if (-not $x -or "$($x.scopes)" -ne $w.scopes -or (Format-PimRfaValue $x.expiresUtc) -ne $w.expiresUtc) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaApiKeys' -PartitionKey 'key' -RowKey $h -Entity @{ id = $w.id; name = $w.name; scopes = $w.scopes; expiresUtc = $w.expiresUtc } } }
            foreach ($h in @($haveK.Keys | Where-Object { -not $wantK.ContainsKey($_) })) { Remove-PimRfaStoreEntity -Store $Store -Table 'RfaApiKeys' -PartitionKey 'key' -RowKey $h }
        }
        $want = @{}; foreach ($e in @(Get-PimRfaEligibilityList -Admins $admins -Departments @($deptIdx.Values) -Companies $companies -Salt $salt -Settings $settings -Assignments $assign -Definitions $defs)) { $want["$($e.accountKey)"] = $e }
        $have = @{}; foreach ($e in @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct')) { $have["$($e.RowKey)"] = $e }
        foreach ($k in @($want.Keys)) {
            $w = $want[$k]; $h = $have[$k]
            $wg = "$($w.groups)"; $wgh = "$($w.groupHours)"
            if (-not $h -or "$($h.contactEmail)" -ne "$($w.contactEmail)" -or "$($h.mode)" -ne "$($w.mode)" -or "$($h.durations)" -ne "$($w.durations)" -or "$($h.groups)" -ne $wg -or "$($h.groupHours)" -ne $wgh) {
                Set-PimRfaStoreEntity -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct' -RowKey $k -Entity @{ contactEmail = $w.contactEmail; mode = $w.mode; durations = $w.durations; groups = $wg; groupHours = $wgh }
            }
        }
        foreach ($k in @($have.Keys | Where-Object { -not $want.ContainsKey($_) })) { Remove-PimRfaStoreEntity -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct' -RowKey $k }
        foreach ($sid in @($reject.Keys)) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey $sid -Entity (@{} + (ConvertTo-PimRfaStoreStatus -Row $storeRows[$sid] -State 'rejected' -Text $reject[$sid])) }
        foreach ($sid in @($forward.Keys)) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey $sid -Entity (@{} + (ConvertTo-PimRfaStoreStatus -Row $storeRows[$sid] -State 'forwarded' -Text $forward[$sid])) }
        foreach ($r in @($keep)) {
            $txt = Get-PimRfaStatusText -Request $r; $we = Format-PimRfaValue $r.windowEndUtc
            foreach ($sid in @($r.storeIds | Where-Object { "$_".Trim() })) {
                $sr = $storeRows["$sid"]
                if (-not $sr -or "$($sr.state)" -ne "$($r.state)" -or "$($sr.statusText)" -ne $txt -or (Format-PimRfaValue $sr.windowEndUtc) -ne $we -or "$($sr.requestId)" -ne "$($r.id)") {
                    Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey "$sid" -Entity (ConvertTo-PimRfaStoreStatus -Row $sr -State "$($r.state)" -Text $txt -WindowEndUtc $we -RequestId "$($r.id)")
                }
            }
        }
        # store rows the portal wrote long ago and that the engine no longer tracks: removed after 30 days
        foreach ($sr in @($storeRows.Values)) {
            $at = ConvertFrom-PimRfaUtc $sr.submittedUtc
            if ($at -and ($now - $at).TotalDays -gt 30 -and -not (& $find "$($sr.RowKey)")) { Remove-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey "$($sr.RowKey)" }
        }
    } catch { $errors.Add("the RFA store could not be updated: $($_.Exception.Message)") }

    $detail = "rfa-sync: $(@($keep).Count) request(s), $touchedAdmins account row(s), $touchedGroups membership row(s), $($mails.Count) mail(s)" + $(if ($log.Count) { ' | ' + ($log -join '; ') }) + $(if ($errors.Count) { ' | ERRORS: ' + ($errors -join '; ') })
    return [pscustomobject]@{ ran = $true; skipped = $false; whatIf = $false; failed = [bool]$errors.Count; detail = $detail }
}

function Get-PimRfaStatusText {
    # PURE. The sentence the portal shows the requester.
    param([Parameter(Mandatory)][object]$Request)
    $end = ConvertFrom-PimRfaUtc $Request.windowEndUtc
    switch ("$($Request.state)") {
        'pending-approval' { return 'Waiting for your sponsor department to approve (at most 24 hours).' }
        'approved'         { return 'Approved -- your account is being enabled.' }
        'active'           { return ("Enabled until {0:yyyy-MM-dd HH:mm} UTC. Activate your roles with MFA." -f $end) }
        'cancel-requested' { return 'Ending early.' }
        'ended'            { return 'Ended -- the account is disabled again.' }
        'cancelled'        { return 'Ended early -- the account is disabled again.' }
        'expired'          { return 'Expired -- nobody decided within 24 hours.' }
        'denied'           { return "Denied$(if ("$($Request.note)".Trim()) { ': ' + $Request.note } else { '.' })" }
    }
    return "$($Request.state)"
}

function ConvertTo-PimRfaStoreStatus {
    # PURE. The store row with the engine's status written into it (the portal's own fields are kept).
    param([AllowNull()][object]$Row, [string]$State, [string]$Text, [string]$WindowEndUtc = '', [string]$RequestId = '')
    $o = [ordered]@{}
    if ($Row) { foreach ($p in $Row.PSObject.Properties) { if ($p.Name -notin @('PartitionKey', 'RowKey', 'Timestamp', 'odata.etag')) { $o[$p.Name] = $p.Value } } }
    $o['state'] = $State; $o['statusText'] = $Text; $o['windowEndUtc'] = $WindowEndUtc; $o['requestId'] = $RequestId
    return $o
}
