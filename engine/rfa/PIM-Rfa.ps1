#Requires -Version 5.1
<#
  §82 REQUEST FOR AUTHORIZATION (RFA) -- the PURE decision core (Pro). REQUIREMENTS §82.5-82.8.

  A disabled admin (typically a consultant) signs in to the public RFA portal with a one-time PIN mailed to the
  ContactEmail on their admin row and asks to have the account ENABLED for a duration from the department's list.
  Auto-approved -> enabled at once; approval required -> any one Owner of the department decides (24 h, then expired).
  The engine (rfa-sync job) applies the outcome to the admin row and ends the window.

  🔴 THE WINDOW IS NEVER AutoDisableDate. A passed AutoDisableDate is OFFBOARDING (Test-PimAdminOffboarded): disable,
  revoke sessions and REMOVE every membership and eligibility. Ending an RFA window that way would wipe a consultant's
  PIM eligibilities at every window end. RFA flips AccountStatus Enabled <-> Disabled (disable only, eligibilities
  kept -- operator 2026-10-02: "Disable only") and keeps the end in its own column RfaWindowEndUtc.

  Everything here is PURE (no Graph, no SQL, no storage, no clock unless -NowUtc is omitted) and PS 5.1-safe.
#>

$script:PimRfaDefaultDurations = @(8, 24, 72)
$script:PimRfaPinMinutes        = 15
$script:PimRfaPinMaxAttempts    = 5
$script:PimRfaLockoutMinutes    = 30
$script:PimRfaApprovalHours     = 24
$script:PimRfaWarnBeforeMinutes = 60
$script:PimRfaOverrideMaxHours  = 744      # 31 days -- IT override (Manager Admin)
$script:PimRfaEmailPattern      = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

function Get-PimRfaRowValue {
    # Read one column off a row that may be a hashtable or an object; '' when absent.
    # 🪤 pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime] (every pim.Rows read does that), and "$date" is
    # then CULTURE text -- a date column would never compare equal to the ISO value it was written as. Dates come back ISO.
    param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return '' }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    else { $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    return (Format-PimRfaValue $v)
}

function Format-PimRfaValue {
    # PURE. A value as text: a [datetime] as UTC ISO ('yyyy-MM-ddTHH:mm:ssZ'), anything else trimmed.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return "$Value".Trim()
}

function ConvertTo-PimRfaMode {
    # 'Auto' / 'Approval' / 'Off' from what an operator types; '' for blank; $null for unreadable.
    param([AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    switch -Regex ($v) {
        '^(?i)(auto|auto-?approved?|automatic)$' { return 'Auto' }
        '^(?i)(approval|approval-?required|approve)$' { return 'Approval' }
        '^(?i)(off|none|disabled|no)$' { return 'Off' }
    }
    return $null
}

function Test-PimRfaIsConsultant {
    # PURE. A consultant = an admin whose Company names a DEFINED company (PIM-Definitions-Companies). The Company
    # column alone is not enough: it is also the account's Entra companyName, which internal admins carry too.
    # §89 (operator 2026-10-02: "company can be both internal and external"): an INTERNAL company (our own, a sister
    # company) is only a label -- its people are not consultants. Type blank = External.
    param([Parameter(Mandatory)][object]$Admin, [object[]]$Companies = @())
    $c = (Get-PimRfaRowValue -Row $Admin -Name 'Company').ToLowerInvariant()
    if (-not $c) { return $false }
    return [bool](@($Companies | Where-Object { (Get-PimRfaRowValue -Row $_ -Name 'Company').ToLowerInvariant() -eq $c -and -not (Test-PimCompanyIsInternal -Company $_) }).Count)
}

function Test-PimCompanyIsInternal {
    # PURE. Type = Internal (case-insensitive); anything else, blank included, is External.
    param([AllowNull()][object]$Company)
    return ((Get-PimRfaRowValue -Row $Company -Name 'Type') -match '^(?i)internal$')
}

function Get-PimRfaEffectiveMode {
    <#
      PURE. The RFA workflow for one admin row. Returns { mode = Off|Auto|Approval; source; reason }.
        * the row's RfaMode wins when set; else the department's RfaMode; else Off.
        * 🔒 a consultant (-IsConsultant: Test-PimRfaIsConsultant) is never auto-approved by the DEPARTMENT default --
          only an explicit RfaMode=Auto on the row itself (IT's deliberate choice) makes a consultant auto-approved.
        * an unreadable value is Off (fail closed) with the reason.
    #>
    param([Parameter(Mandatory)][object]$Admin, [AllowNull()][object]$Department, [switch]$IsConsultant)
    $rowRaw  = Get-PimRfaRowValue -Row $Admin -Name 'RfaMode'
    $deptRaw = Get-PimRfaRowValue -Row $Department -Name 'RfaMode'
    $row = ConvertTo-PimRfaMode -Value $rowRaw
    if ($null -eq $row) { return [pscustomobject]@{ mode = 'Off'; source = 'row'; reason = "the row's RfaMode '$rowRaw' is not Off / Auto / Approval -- RFA is off for this account" } }
    if ($row) { return [pscustomobject]@{ mode = $row; source = 'row'; reason = "RfaMode=$row on the admin row" } }
    $dep = ConvertTo-PimRfaMode -Value $deptRaw
    if ($null -eq $dep) { return [pscustomobject]@{ mode = 'Off'; source = 'department'; reason = "the department's RfaMode '$deptRaw' is not Off / Auto / Approval -- RFA is off" } }
    if (-not $dep) { return [pscustomobject]@{ mode = 'Off'; source = 'default'; reason = 'no RfaMode on the row or the department (default Off)' } }
    if ($dep -eq 'Auto' -and $IsConsultant) {
        return [pscustomobject]@{ mode = 'Approval'; source = 'department'; reason = 'the department is auto-approved, but a Company-linked consultant always needs approval unless the admin row itself says RfaMode=Auto' }
    }
    return [pscustomobject]@{ mode = $dep; source = 'department'; reason = "RfaMode=$dep on the department" }
}

function Get-PimRfaDurations {
    # PURE. The allowed window lengths in hours from the department's RfaDurations ('8|24|72'); default 8 / 24 / 72.
    # Values outside 1..IT-override-max are dropped; nothing usable left = the default.
    param([AllowNull()][object]$Department)
    $raw = Get-PimRfaRowValue -Row $Department -Name 'RfaDurations'
    $out = @()
    foreach ($p in @("$raw" -split '[|;,\s]+')) {
        $n = 0
        if ([int]::TryParse("$p".Trim().TrimEnd('h', 'H'), [ref]$n) -and $n -ge 1 -and $n -le $script:PimRfaOverrideMaxHours) { $out += $n }
    }
    $out = @($out | Sort-Object -Unique)
    if (-not $out.Count) { return @($script:PimRfaDefaultDurations) }
    return @($out)
}

function Get-PimRfaEligibility {
    <#
      PURE. May this admin use RFA at all? Returns { eligible; mode; durations; contactEmail; reason }.
      Refused: mode Off, no / malformed ContactEmail, AccountStatus Revoked, Lifecycle Retire, an offboarding date.
    #>
    param([Parameter(Mandatory)][object]$Admin, [AllowNull()][object]$Department, [switch]$IsConsultant)
    $m = Get-PimRfaEffectiveMode -Admin $Admin -Department $Department -IsConsultant:$IsConsultant
    $mail = Get-PimRfaRowValue -Row $Admin -Name 'ContactEmail'
    $no = { param($r) [pscustomobject]@{ eligible = $false; mode = $m.mode; durations = @(); contactEmail = $mail; reason = $r } }
    if ($m.mode -eq 'Off') { return (& $no $m.reason) }
    if (-not $mail) { return (& $no 'no ContactEmail on the admin row -- the PIN has nowhere to go') }
    if ($mail -notmatch $script:PimRfaEmailPattern) { return (& $no "ContactEmail '$mail' is not an e-mail address") }
    if ((Get-PimRfaRowValue -Row $Admin -Name 'AccountStatus') -ieq 'Revoked') { return (& $no 'AccountStatus=Revoked -- a revoked account cannot be re-enabled by request') }
    if ((Get-PimRfaRowValue -Row $Admin -Name 'Lifecycle') -match '(?i)^retire') { return (& $no 'Lifecycle=Retire -- the account is being offboarded') }
    if ((Get-PimRfaRowValue -Row $Admin -Name 'AutoDisableDate') -or (Get-PimRfaRowValue -Row $Admin -Name 'OffboardDate')) {
        return (& $no 'the row carries an AutoDisableDate (offboarding) -- RFA does not enable an account that is scheduled for offboarding')
    }
    return [pscustomobject]@{ eligible = $true; mode = $m.mode; durations = @(Get-PimRfaDurations -Department $Department); contactEmail = $mail; reason = $m.reason }
}

function Get-PimRfaHash {
    # PURE. Lower-case hex SHA-256 of salt + text (UTF-8).
    param([AllowEmptyString()][string]$Salt, [AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Salt$Text")) } finally { $sha.Dispose() }
    return (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-PimRfaAccountKey {
    # PURE. The published key for an account: salted hash of the lower-case UPN (the island never holds the UPN list).
    param([Parameter(Mandatory)][string]$Salt, [Parameter(Mandatory)][string]$UserPrincipalName)
    return (Get-PimRfaHash -Salt $Salt -Text "$UserPrincipalName".Trim().ToLowerInvariant())
}

function New-PimRfaPinChallenge {
    <#
      A 6-digit one-time PIN (CSPRNG, no modulo bias) and the record to store: only a salted HASH of the code.
      Returns { code; record = { accountKey; salt; hash; createdUtc; expiresUtc; attempts; lockedUntilUtc; used } }.
      -Bytes injects the random source for tests.
    #>
    param([Parameter(Mandatory)][string]$AccountKey, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Bytes)
    $get = if ($Bytes) { $Bytes } else { { param($n) $b = New-Object byte[] $n; $r = [System.Security.Cryptography.RandomNumberGenerator]::Create(); try { $r.GetBytes($b) } finally { $r.Dispose() }; ,$b } }
    $code = $null
    for ($i = 0; $i -lt 32 -and $null -eq $code; $i++) {
        $b = & $get 4
        $v = [BitConverter]::ToUInt32([byte[]]$b, 0)
        if ($v -lt 4294000000) { $code = '{0:D6}' -f ($v % 1000000) }   # 4294000000 is a multiple of 10^6: no bias
    }
    if ($null -eq $code) { throw 'New-PimRfaPinChallenge: the random source gave no usable value' }
    $salt = ((& $get 16) | ForEach-Object { $_.ToString('x2') }) -join ''
    $now = $NowUtc.ToUniversalTime()
    return [pscustomobject]@{
        code   = $code
        record = [pscustomobject]@{ accountKey = $AccountKey; salt = $salt; hash = (Get-PimRfaHash -Salt $salt -Text $code)
                                    createdUtc = $now.ToString('o'); expiresUtc = $now.AddMinutes($script:PimRfaPinMinutes).ToString('o')
                                    attempts = 0; lockedUntilUtc = ''; used = $false }
    }
}

function ConvertFrom-PimRfaUtc {
    # PURE. ISO text -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
    return $null
}

function Test-PimRfaPin {
    <#
      PURE. Check a typed PIN against the stored record. Returns { ok; reason; record } -- the caller STORES the
      returned record (attempts / lock / used change on every call). Rules: 15 min, one use, 5 wrong tries then a
      30-minute lockout. Constant-time compare of the hashes.
    #>
    param([AllowNull()][object]$Record, [AllowEmptyString()][string]$Code, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    if ($null -eq $Record) { return [pscustomobject]@{ ok = $false; reason = 'no PIN was requested'; record = $null } }
    $r = [pscustomobject]@{ accountKey = "$($Record.accountKey)"; salt = "$($Record.salt)"; hash = "$($Record.hash)"; createdUtc = "$($Record.createdUtc)"
                            expiresUtc = "$($Record.expiresUtc)"; attempts = [int]("0$($Record.attempts)"); lockedUntilUtc = "$($Record.lockedUntilUtc)"; used = [bool]$Record.used }
    $lock = ConvertFrom-PimRfaUtc $r.lockedUntilUtc
    if ($lock -and $lock -gt $now) { return [pscustomobject]@{ ok = $false; reason = ("locked after {0} wrong PINs until {1:HH:mm} UTC" -f $script:PimRfaPinMaxAttempts, $lock); record = $r } }
    if ($r.used) { return [pscustomobject]@{ ok = $false; reason = 'this PIN was already used -- request a new one'; record = $r } }
    $exp = ConvertFrom-PimRfaUtc $r.expiresUtc
    if (-not $exp -or $exp -le $now) { return [pscustomobject]@{ ok = $false; reason = 'the PIN has expired -- request a new one'; record = $r } }
    $want = $r.hash; $got = Get-PimRfaHash -Salt $r.salt -Text ("$Code".Trim())
    $diff = $want.Length -bxor $got.Length
    for ($i = 0; $i -lt [Math]::Min($want.Length, $got.Length); $i++) { $diff = $diff -bor ([int][char]$want[$i] -bxor [int][char]$got[$i]) }
    if ($diff -eq 0 -and "$Code".Trim() -match '^\d{6}$') {
        $r.used = $true
        return [pscustomobject]@{ ok = $true; reason = 'PIN accepted'; record = $r }
    }
    $r.attempts++
    if ($r.attempts -ge $script:PimRfaPinMaxAttempts) {
        $r.lockedUntilUtc = $now.AddMinutes($script:PimRfaLockoutMinutes).ToString('o')
        return [pscustomobject]@{ ok = $false; reason = ("wrong PIN -- locked for {0} minutes" -f $script:PimRfaLockoutMinutes); record = $r }
    }
    return [pscustomobject]@{ ok = $false; reason = ("wrong PIN ({0} of {1} tries left)" -f ($script:PimRfaPinMaxAttempts - $r.attempts), $script:PimRfaPinMaxAttempts); record = $r }
}

function Test-PimRfaRateLimit {
    <#
      PURE. Sliding-window limit. -Hits = earlier hit times (any order). Returns { allowed; retryAfterSeconds; hits }
      where hits = the window's hits plus this one when allowed (store it). Used per account (PIN requests) and per
      source address (every portal call).
    #>
    param([object[]]$Hits = @(), [int]$Max = 5, [int]$WindowMinutes = 15, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime(); $from = $now.AddMinutes(-$WindowMinutes)
    $in = @(@($Hits) | ForEach-Object { ConvertFrom-PimRfaUtc $_ } | Where-Object { $_ -and $_ -gt $from } | Sort-Object)
    if ($in.Count -ge $Max) {
        $retry = [int][Math]::Ceiling(($in[0].AddMinutes($WindowMinutes) - $now).TotalSeconds)
        return [pscustomobject]@{ allowed = $false; retryAfterSeconds = [Math]::Max(1, $retry); hits = @($in | ForEach-Object { $_.ToString('o') }) }
    }
    return [pscustomobject]@{ allowed = $true; retryAfterSeconds = 0; hits = @(@($in) + $now | ForEach-Object { $_.ToString('o') }) }
}

function New-PimRfaRequest {
    <#
      PURE. Build a request, or refuse. Returns { ok; reason; request }.
        -Source portal : the account must be eligible; -Hours must be in the department's list.
        -Source api    : ServiceNow owns the approval -- the request is created APPROVED; Kind enable or group
                         (group needs -GroupName); hours 1..744; -ExternalRef (the ticket) is required (idempotency).
        -Override      : a Manager Admin's long window (<= 744 h), created APPROVED by that admin.
    #>
    param(
        [Parameter(Mandatory)][object]$Admin, [AllowNull()][object]$Department,
        [Parameter(Mandatory)][int]$Hours,
        [ValidateSet('portal', 'api', 'override')][string]$Source = 'portal',
        [ValidateSet('enable', 'group')][string]$Kind = 'enable',
        [string]$GroupName = '', [string]$ExternalRef = '', [string]$RequestedBy = '', [string]$Reason = '',
        [datetime]$NowUtc = [datetime]::UtcNow, [string]$Id = '', [switch]$IsConsultant
    )
    $upn = Get-PimRfaRowValue -Row $Admin -Name 'UserPrincipalName'
    $no = { param($r) [pscustomobject]@{ ok = $false; reason = $r; request = $null } }
    if (-not $upn) { return (& $no 'the admin row has no UserPrincipalName') }
    if ($Kind -eq 'group' -and $Source -ne 'api') { return (& $no 'a group membership can only be requested through the API') }
    if ($Kind -eq 'group' -and -not "$GroupName".Trim()) { return (& $no 'a group request needs the group name') }
    $state = 'pending-approval'; $mode = ''
    switch ($Source) {
        'portal' {
            $el = Get-PimRfaEligibility -Admin $Admin -Department $Department -IsConsultant:$IsConsultant
            if (-not $el.eligible) { return (& $no $el.reason) }
            if (@($el.durations) -notcontains $Hours) { return (& $no ("{0} h is not offered -- choose {1} h" -f $Hours, (@($el.durations) -join ' / '))) }
            $mode = $el.mode
            if ($mode -eq 'Auto') { $state = 'approved' }
        }
        'api' {
            if (-not "$ExternalRef".Trim()) { return (& $no 'an API request needs its ticket number (ExternalRef) -- it makes a repeated call idempotent') }
            if ($Hours -lt 1 -or $Hours -gt $script:PimRfaOverrideMaxHours) { return (& $no ("hours must be 1..{0}" -f $script:PimRfaOverrideMaxHours)) }
            if ((Get-PimRfaRowValue -Row $Admin -Name 'AccountStatus') -ieq 'Revoked') { return (& $no 'AccountStatus=Revoked -- a revoked account cannot be re-enabled by request') }
            $state = 'approved'; $mode = 'External'
        }
        'override' {
            if ($Hours -lt 1 -or $Hours -gt $script:PimRfaOverrideMaxHours) { return (& $no ("an IT override is at most {0} days" -f ($script:PimRfaOverrideMaxHours / 24))) }
            if (-not "$RequestedBy".Trim()) { return (& $no 'an IT override must name the Manager Admin who grants it') }
            if ((Get-PimRfaRowValue -Row $Admin -Name 'AccountStatus') -ieq 'Revoked') { return (& $no 'AccountStatus=Revoked -- a revoked account cannot be re-enabled by request') }
            $state = 'approved'; $mode = 'Override'
        }
    }
    $now = $NowUtc.ToUniversalTime()
    $rid = if ("$Id".Trim()) { "$Id".Trim() } elseif ($Source -eq 'api') { 'api-' + (Get-PimRfaHash -Salt '' -Text "$ExternalRef|$Kind|$upn|$GroupName".ToLowerInvariant()).Substring(0, 24) } else { [guid]::NewGuid().ToString('n') }
    $req = [pscustomobject]@{
        id = $rid; kind = $Kind; upn = $upn.ToLowerInvariant(); groupName = "$GroupName".Trim(); hours = $Hours; source = $Source; mode = $mode
        externalRef = "$ExternalRef".Trim(); requestedBy = $(if ("$RequestedBy".Trim()) { "$RequestedBy".Trim() } else { $upn.ToLowerInvariant() })
        reason = "$Reason".Trim(); department = (Get-PimRfaRowValue -Row $Admin -Name 'Department'); company = (Get-PimRfaRowValue -Row $Admin -Name 'Company')
        state = $state; requestedUtc = $now.ToString('o'); decidedBy = $(if ($state -eq 'approved') { if ($Source -eq 'portal') { 'auto' } else { "$RequestedBy".Trim() } } else { '' })
        decidedUtc = $(if ($state -eq 'approved') { $now.ToString('o') } else { '' }); windowStartUtc = ''; windowEndUtc = ''; warnedUtc = ''; endedUtc = ''; note = ''
    }
    return [pscustomobject]@{ ok = $true; reason = $(if ($state -eq 'approved') { "approved ($mode)" } else { 'waiting for a department Owner' }); request = $req }
}

function Set-PimRfaDecision {
    <#
      PURE. An Owner's decision on a pending request. Returns { ok; reason; request }.
      Any ONE Owner of the request's department may decide (operator 2026-10-02); the requester never decides their
      own request; a Manager Admin may also decide (-IsAdmin). Only a pending, unexpired request can be decided.
    #>
    param([Parameter(Mandatory)][object]$Request, [ValidateSet('approve', 'deny')][string]$Decision,
          [Parameter(Mandatory)][string]$By, [string[]]$DepartmentOwners = @(), [switch]$IsAdmin,
          [string]$Note = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $by = "$By".Trim().ToLowerInvariant()
    $r = $Request.PSObject.Copy()
    if ("$($r.state)" -ne 'pending-approval') { return [pscustomobject]@{ ok = $false; reason = "the request is '$($r.state)', not waiting for a decision"; request = $Request } }
    if ((Get-PimRfaRequestStep -Request $r -NowUtc $NowUtc).action -eq 'expire') { return [pscustomobject]@{ ok = $false; reason = 'the request has expired (no decision within 24 h)'; request = $Request } }
    if ($by -eq "$($r.upn)".ToLowerInvariant()) { return [pscustomobject]@{ ok = $false; reason = 'nobody approves their own request'; request = $Request } }
    $owners = @($DepartmentOwners | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if (-not $IsAdmin -and $owners -notcontains $by) { return [pscustomobject]@{ ok = $false; reason = "$By is not an Owner of department '$($r.department)'"; request = $Request } }
    $r.state = $(if ($Decision -eq 'approve') { 'approved' } else { 'denied' })
    $r.decidedBy = $by; $r.decidedUtc = $NowUtc.ToUniversalTime().ToString('o'); $r.note = "$Note".Trim()
    return [pscustomobject]@{ ok = $true; reason = "$($r.state) by $by"; request = $r }
}

function Get-PimRfaRequestStep {
    <#
      PURE. What the engine does with this request now. Returns { action; reason }:
        expire      pending > 24 h                         -> state expired, requester told
        enable      approved, window not started           -> AccountStatus=Enabled, window = now .. now+hours
        warn-ending active, <= 60 min left, not yet warned -> mail the person (may request an extension)
        end         active, window over                    -> AccountStatus=Disabled (disable only)
        cancel      cancel-requested                       -> end at once (AccountStatus=Disabled if it was active)
        none        nothing to do
    #>
    param([Parameter(Mandatory)][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime(); $st = "$($Request.state)"
    switch ($st) {
        'pending-approval' {
            $at = ConvertFrom-PimRfaUtc $Request.requestedUtc
            if (-not $at -or $now -ge $at.AddHours($script:PimRfaApprovalHours)) { return [pscustomobject]@{ action = 'expire'; reason = 'no decision within 24 h' } }
        }
        'approved' { return [pscustomobject]@{ action = 'enable'; reason = 'approved -- enable the account for the window' } }
        'active' {
            $end = ConvertFrom-PimRfaUtc $Request.windowEndUtc
            if (-not $end -or $now -ge $end) { return [pscustomobject]@{ action = 'end'; reason = 'the window is over' } }
            if (-not "$($Request.warnedUtc)".Trim() -and ($end - $now).TotalMinutes -le $script:PimRfaWarnBeforeMinutes) { return [pscustomobject]@{ action = 'warn-ending'; reason = 'one hour or less left' } }
        }
        'cancel-requested' { return [pscustomobject]@{ action = 'cancel'; reason = 'cancelled before the end' } }
    }
    return [pscustomobject]@{ action = 'none'; reason = '' }
}

function Invoke-PimRfaRequestStep {
    <#
      PURE. Apply a step's STATE change to the request (the caller performs the row change from
      Get-PimRfaAdminRowChange and only then stores the returned request). Returns the new request.
    #>
    param([Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][string]$Action, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime(); $r = $Request.PSObject.Copy()
    switch ($Action) {
        'expire'      { $r.state = 'expired'; $r.endedUtc = $now.ToString('o') }
        'enable'      { $r.state = 'active'; $r.windowStartUtc = $now.ToString('o'); $r.windowEndUtc = $now.AddHours([int]$r.hours).ToString('o') }
        'warn-ending' { $r.warnedUtc = $now.ToString('o') }
        'end'         { $r.state = 'ended'; $r.endedUtc = $now.ToString('o') }
        'cancel'      { $r.state = 'cancelled'; $r.endedUtc = $now.ToString('o') }
    }
    return $r
}

function Get-PimRfaAdminRowChange {
    <#
      PURE. The admin-row change for an 'enable' or an 'end' / 'cancel' step of an ENABLE request. Returns
      @{ AccountStatus; RfaWindowEndUtc } or $null (nothing to change).
        enable : AccountStatus=Enabled, RfaWindowEndUtc = the window end (a LATER end already on the row is kept: two
                 overlapping windows never shorten each other).
        end    : AccountStatus=Disabled, RfaWindowEndUtc cleared -- unless ANOTHER active window on this account
                 still runs (-OtherActiveEndUtc), then nothing changes.
      Never AutoDisableDate (that is offboarding -- see the file header).
    #>
    param([Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][string]$Action, [AllowNull()][object]$Admin,
          [object[]]$OtherActiveEndUtc = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    if ("$($Request.kind)" -ne 'enable') { return $null }
    $now = $NowUtc.ToUniversalTime()
    if ($Action -eq 'enable') {
        $end = ConvertFrom-PimRfaUtc $Request.windowEndUtc
        if (-not $end) { $end = $now.AddHours([int]$Request.hours) }
        $cur = ConvertFrom-PimRfaUtc (Get-PimRfaRowValue -Row $Admin -Name 'RfaWindowEndUtc')
        if ($cur -and $cur -gt $end) { $end = $cur }
        return [ordered]@{ AccountStatus = 'Enabled'; RfaWindowEndUtc = $end.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    }
    if ($Action -in @('end', 'cancel')) {
        $still = @(@($OtherActiveEndUtc) | ForEach-Object { ConvertFrom-PimRfaUtc $_ } | Where-Object { $_ -and $_ -gt $now })
        if ($still.Count) { return $null }
        return [ordered]@{ AccountStatus = 'Disabled'; RfaWindowEndUtc = '' }
    }
    return $null
}

function Get-PimRfaEligibilityList {
    <#
      PURE. What the engine publishes to the RFA store: ONLY eligible accounts, keyed by a salted hash of the UPN,
      with the PIN address, the mode and the offered durations. No UPN, no name, no roles, no groups.
    #>
    param([object[]]$Admins = @(), [object[]]$Departments = @(), [object[]]$Companies = @(), [Parameter(Mandatory)][string]$Salt)
    $byDept = @{}
    foreach ($d in @($Departments)) { $k = (Get-PimRfaRowValue -Row $d -Name 'Department').ToLowerInvariant(); if ($k -and -not $byDept.ContainsKey($k)) { $byDept[$k] = $d } }
    $out = @()
    foreach ($a in @($Admins)) {
        $upn = Get-PimRfaRowValue -Row $a -Name 'UserPrincipalName'
        if (-not $upn) { continue }
        $dep = $byDept[(Get-PimRfaRowValue -Row $a -Name 'Department').ToLowerInvariant()]
        $el = Get-PimRfaEligibility -Admin $a -Department $dep -IsConsultant:(Test-PimRfaIsConsultant -Admin $a -Companies $Companies)
        if (-not $el.eligible) { continue }
        $out += [pscustomobject]@{ accountKey = (Get-PimRfaAccountKey -Salt $Salt -UserPrincipalName $upn); contactEmail = $el.contactEmail; mode = $el.mode; durations = (@($el.durations) -join '|') }
    }
    return @($out)
}
