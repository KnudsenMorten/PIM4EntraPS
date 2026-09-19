<#
  PIM-BreakGlassChange.ps1 -- MAKER/CHECKER for the break-glass ACCOUNT list (operator 2026-09-19:
  "build the break-glass maker/checker").

  WHY THIS FILE EXISTS
  --------------------
  pim.Settings['BreakGlassAccounts'] (PIM-BreakGlassAccounts.ps1) EXEMPTS accounts from every revoke,
  disable, session-revoke and offboard path. Until now one SuperAdmin could change it in the Manager and
  it applied at once -- so one person could shield any account from every guard PIM has. That is a
  tier-0 control; it now needs a SECOND SuperAdmin.

  THE MODEL
  ---------
  * The Manager's PUT no longer writes the list. It raises a PENDING change request holding the proposed
    list (normalised exactly as Set-PimBreakGlassAccountList validates it), the SNAPSHOT hash of the list
    the maker saw (Get-PimBreakGlassListHash), the diff (added / removed), the justification, the maker,
    and created / expiry times (default 72 h).
  * ONE open request at a time. A second request while one is open is refused (409); the maker may cancel
    their own.
  * A DIFFERENT SuperAdmin approves (maker != checker, case-insensitive on the normalised identity).
    Approve re-reads the stored list: a list that changed since the request was made is refused and the
    request closes as STALE. Otherwise the list is written with a compare-and-set against that snapshot
    (Set-PimBreakGlassAccountList -ExpectedSnapshotHash), read back, and the request closes as APPLIED.
  * Any OTHER SuperAdmin may reject; the maker may cancel. An expired request can never be approved.

  🔒 ALWAYS ON. This gate does NOT consult the 'makerchecker' feature flag or the 'approvalsPreview'
  governance preview (both default OFF). Those gate OPTIONAL workflows; the break-glass list is the tier-0
  exemption list itself -- the one setting that switches every other guard off for an account -- and a
  control that protects it cannot be one a single SuperAdmin can also switch off.

  WHY A DEDICATED pim.Settings ROW, NOT THE APPROVAL QUEUE (pim.Settings['ApprovalRequests'])
  ------------------------------------------------------------------------------------------
    1. That queue's endpoints sit behind the approvalsPreview flag (default off); this gate is always on.
    2. Its checker honours $global:PIM_AllowSelfApprove (self-approval for a single-operator lab). This
       gate has NO self-approve switch: the documented route for a one-SuperAdmin environment is the
       host-side operator script (tools/setup/Set-PimBreakGlassAccounts.ps1), audited as 'setup'.
    3. Its consumers (offboard / revoke / disable / authoring gates, the engine) read the whole queue;
       a record they must learn to ignore is a record one of them will one day act on. A separate row
       is ignored by construction -- the engine never reads it.
    4. It needs states that queue does not have (applied / stale / cancelled / failed) and a
       compare-and-set write, so two approvals, or an approval racing a cancel, cannot both win.
  The row is pim.Settings['BreakGlassAccountsChange'] and holds the MOST RECENT request (open or closed);
  the full history is the audit trail (settings.breakglass-accounts.*).

  PURE core (no I/O): Get-PimBreakGlassListDiff, Resolve-PimBreakGlassChangeCreate,
  Resolve-PimBreakGlassChangeDecision, Test-PimBreakGlassChangeOpen, Get-PimBreakGlassCheckerCandidates.
  Store adapter (compare-and-set over pim.Settings): Get-PimBreakGlassChangeRequest,
  New-PimBreakGlassChangeRequest, Invoke-PimBreakGlassChangeApproval, Close-PimBreakGlassChangeRequest.
  Every store operation THROWS on a store failure (PIM v2 is SQL-only: no file, no memory fallback).
  PS 5.1-safe (no ?./??, no ternary).
#>

Set-StrictMode -Off

if (-not (Get-Command Get-PimBreakGlassListHash -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-BreakGlassAccounts.ps1') }

function Get-PimBreakGlassChangeSettingName { 'BreakGlassAccountsChange' }

function Get-PimBreakGlassChangeTtlHours {
    # How long a request may wait for a checker. Default 72 h; $global:PIM_BreakGlassChangeTtlHours
    # (1..168) overrides it.
    $v = $global:PIM_BreakGlassChangeTtlHours
    if ($null -ne $v -and "$v" -match '^\d+$' -and [int]$v -ge 1 -and [int]$v -le 168) { return [int]$v }
    return 72
}

function ConvertTo-PimBreakGlassIdentityKey {
    # PURE. The identity as the rest of the Manager compares it (Get-PimManagerRole, /api/approvals):
    # trimmed, lower-case invariant -- a UPN or an object id.
    param([AllowNull()][string]$Identity)
    return "$Identity".Trim().ToLowerInvariant()
}

function ConvertTo-PimBreakGlassChangeUtcText {
    # PURE. Any time shape (a [datetime] -- pwsh 7's ConvertFrom-Json turns ISO text into one -- or text)
    # -> round-trip ISO 8601 UTC text, '' when absent/unparseable.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime().ToString('o') }
    $s = "$Value".Trim()
    if (-not $s) { return '' }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt.ToUniversalTime().ToString('o') }
    return ''
}

function ConvertTo-PimBreakGlassChangeUtc {
    param([AllowNull()][object]$Value)
    $t = ConvertTo-PimBreakGlassChangeUtcText -Value $Value
    if (-not $t) { return $null }
    return ([datetime]::Parse($t, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime()
}

function ConvertTo-PimBreakGlassChangeRecord {
    <#
      PURE. Rebuild a request from ANY parsed shape into one canonical ordered hashtable: every list an
      array, every time ISO text. ConvertFrom-Json differs between hosts (5.1 collapses one-element arrays
      in some shapes, pwsh 7 turns ISO strings into [datetime]); normalising here means the record that is
      compared, displayed and written back is the same on both. $null in -> $null out.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $s = "$Value".Trim()
        if (-not $s -or $s -eq 'null') { return $null }
        try { $Value = $s | ConvertFrom-Json } catch { throw "pim.Settings['$(Get-PimBreakGlassChangeSettingName)'] is not valid JSON: $($_.Exception.Message)" }
        if ($null -eq $Value) { return $null }
    }
    $get = {
        param($o, $n)
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] } return $null }
        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value } return $null
    }
    $lst = { param($v) $o = @(); foreach ($x in @($v)) { if ($null -ne $x -and "$x".Trim()) { $o += "$x".Trim() } }; return ,$o }
    $r = [ordered]@{}
    $r.id            = "$(& $get $Value 'id')"
    $r.status        = "$(& $get $Value 'status')".Trim().ToLowerInvariant()
    $r.proposed      = & $lst (& $get $Value 'proposed')
    $r.snapshot      = & $lst (& $get $Value 'snapshot')
    $r.snapshotHash  = "$(& $get $Value 'snapshotHash')".Trim().ToLowerInvariant()
    $r.added         = & $lst (& $get $Value 'added')
    $r.removed       = & $lst (& $get $Value 'removed')
    $r.justification = "$(& $get $Value 'justification')"
    $r.maker         = "$(& $get $Value 'maker')"
    $r.confirmEmpty  = [bool](& $get $Value 'confirmEmpty')
    $r.createdUtc    = ConvertTo-PimBreakGlassChangeUtcText -Value (& $get $Value 'createdUtc')
    $r.expiresUtc    = ConvertTo-PimBreakGlassChangeUtcText -Value (& $get $Value 'expiresUtc')
    $r.checker       = "$(& $get $Value 'checker')"
    $r.decidedUtc    = ConvertTo-PimBreakGlassChangeUtcText -Value (& $get $Value 'decidedUtc')
    $r.closedBy      = "$(& $get $Value 'closedBy')"
    $r.closedUtc     = ConvertTo-PimBreakGlassChangeUtcText -Value (& $get $Value 'closedUtc')
    $r.closeNote     = "$(& $get $Value 'closeNote')"
    $r.applied       = & $lst (& $get $Value 'applied')
    return $r
}

function ConvertTo-PimBreakGlassChangeJson {
    # PURE. The canonical stored text of a request.
    param([AllowNull()][object]$Request)
    if ($null -eq $Request) { return $null }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    return (ConvertTo-Json -InputObject $r -Depth 6 -Compress)
}

# ---- pure core --------------------------------------------------------------------------------
function Get-PimBreakGlassListDiff {
    # PURE. What a change does: added / removed (normalised, sorted ordinally) and whether it changes anything.
    param([AllowNull()][AllowEmptyCollection()][object]$Current, [AllowNull()][AllowEmptyCollection()][object]$Proposed)
    $cur = @(ConvertTo-PimBreakGlassList -Value $Current)
    $new = @(ConvertTo-PimBreakGlassList -Value $Proposed)
    $added = [string[]]@($new | Where-Object { $cur -notcontains $_ })
    $removed = [string[]]@($cur | Where-Object { $new -notcontains $_ })
    [Array]::Sort($added, [System.StringComparer]::Ordinal)
    [Array]::Sort($removed, [System.StringComparer]::Ordinal)
    return [pscustomobject]@{ added = @($added); removed = @($removed); changed = [bool](@($added).Count -or @($removed).Count) }
}

function Test-PimBreakGlassChangeOpen {
    # PURE. Is this request still waiting for a decision (pending AND inside its window) as of NowUtc?
    param([AllowNull()][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Request) { return $false }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    if ($r.status -ne 'pending') { return $false }
    $exp = ConvertTo-PimBreakGlassChangeUtc -Value $r.expiresUtc
    if ($null -eq $exp) { return $false }          # an unreadable expiry is expired: it can never be approved
    return ($NowUtc.ToUniversalTime() -lt $exp)
}

function Test-PimBreakGlassChangeApplying {
    # PURE. A request a checker has claimed ('approved') whose write has not been recorded yet. Blocks a
    # new request for 10 minutes so the claim can be completed; after that it is an interrupted apply.
    param([AllowNull()][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Request) { return $false }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    if ($r.status -ne 'approved') { return $false }
    $d = ConvertTo-PimBreakGlassChangeUtc -Value $r.decidedUtc
    if ($null -eq $d) { return $false }
    return (($NowUtc.ToUniversalTime() - $d).TotalMinutes -lt 10)
}

function Resolve-PimBreakGlassChangeExpiry {
    # PURE. A pending request past its window -> the same request closed as 'expired' (changed=$true).
    param([AllowNull()][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Request) { return [pscustomobject]@{ request = $null; changed = $false } }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    if ($r.status -eq 'pending' -and -not (Test-PimBreakGlassChangeOpen -Request $r -NowUtc $NowUtc)) {
        $r.status = 'expired'; $r.closedUtc = $NowUtc.ToUniversalTime().ToString('o'); $r.closedBy = ''
        $r.closeNote = 'expired before a second SuperAdmin approved it'
        return [pscustomobject]@{ request = $r; changed = $true }
    }
    return [pscustomobject]@{ request = $r; changed = $false }
}

function Resolve-PimBreakGlassChangeCreate {
    <#
      PURE maker decision. Returns @{ ok; code; reason; request; expiredPrevious }.
        code: created | invalid | no-justification | no-maker | no-change | confirm-empty | open-request
      -Current is the STORED list now (store row only, not the legacy env union -- that is what is edited).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Existing,
        [AllowNull()][AllowEmptyCollection()][object]$Current,
        [AllowNull()][AllowEmptyCollection()][string[]]$Proposed,
        [string]$Maker,
        [string]$Justification,
        [switch]$ConfirmEmpty,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$TtlHours = -1
    )
    $out = { param($ok, $code, $reason, $req, $prev) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req; expiredPrevious = $prev } }
    if (-not "$Maker".Trim()) { return (& $out $false 'no-maker' 'the maker identity is unknown -- a request must name who raised it' $null $null) }
    if (-not "$Justification".Trim()) { return (& $out $false 'no-justification' 'justification is required -- this list exempts accounts from every disable, revoke and offboard guard.' $null $null) }
    $bad = @(@($Proposed) | Where-Object { "$_".Trim() -and -not (Test-PimBreakGlassAccountEntry -Value "$_") })
    if ($bad.Count) { return (& $out $false 'invalid' ("invalid break-glass entr{0}: {1} -- each entry must be a UPN or an object id" -f $(if ($bad.Count -eq 1) { 'y' } else { 'ies' }), ($bad -join ', ')) $null $null) }
    $new = @(ConvertTo-PimBreakGlassList -Value @($Proposed))
    $cur = @(ConvertTo-PimBreakGlassList -Value $Current)
    $ex = Resolve-PimBreakGlassChangeExpiry -Request $Existing -NowUtc $NowUtc
    $prev = $null
    if ($ex.request) {
        if (Test-PimBreakGlassChangeOpen -Request $ex.request -NowUtc $NowUtc) {
            return (& $out $false 'open-request' ("a break-glass change request is already open (raised by {0}, expires {1}) -- a second SuperAdmin must approve or reject it, or its maker cancel it, before another is raised" -f $ex.request.maker, $ex.request.expiresUtc) $ex.request $null)
        }
        if (Test-PimBreakGlassChangeApplying -Request $ex.request -NowUtc $NowUtc) {
            return (& $out $false 'open-request' ("a break-glass change approved by {0} is being applied right now -- reload and raise a new request against the result" -f $ex.request.checker) $ex.request $null)
        }
        if ($ex.changed) { $prev = $ex.request }
    }
    # An empty proposal is confirmed first, whatever is stored: the warning is about intent, not the diff.
    if ($new.Count -eq 0 -and -not $ConfirmEmpty) {
        return (& $out $false 'confirm-empty' 'an EMPTY break-glass list removes the protection from every emergency account. Send confirmEmpty=true if that is really the intent.' $null $prev)
    }
    $diff = Get-PimBreakGlassListDiff -Current $cur -Proposed $new
    if (-not $diff.changed) { return (& $out $false 'no-change' 'the proposed list is the list already stored -- there is nothing to approve' $null $prev) }
    if ($TtlHours -lt 1) { $TtlHours = Get-PimBreakGlassChangeTtlHours }
    $now = $NowUtc.ToUniversalTime()
    $req = [ordered]@{
        id = [guid]::NewGuid().ToString(); status = 'pending'
        proposed = @($new); snapshot = @($cur); snapshotHash = (Get-PimBreakGlassListHash -Accounts $cur)
        added = @($diff.added); removed = @($diff.removed)
        justification = "$Justification".Trim(); maker = "$Maker".Trim(); confirmEmpty = [bool]$ConfirmEmpty
        createdUtc = $now.ToString('o'); expiresUtc = $now.AddHours($TtlHours).ToString('o')
        checker = ''; decidedUtc = ''; closedBy = ''; closedUtc = ''; closeNote = ''; applied = @()
    }
    return (& $out $true 'created' ("request raised -- a SECOND SuperAdmin must approve it before it applies (expires {0})" -f $req.expiresUtc) (ConvertTo-PimBreakGlassChangeRecord -Value $req) $prev)
}

function Resolve-PimBreakGlassChangeDecision {
    <#
      PURE checker decision. -Decision approve | reject | cancel. Returns @{ ok; code; reason; request }.
        code: approved | rejected | cancelled | not-found | wrong-request | not-pending | expired |
              same-person | not-maker | stale
      approve : a SuperAdmin who is NOT the maker; the stored list must still hash to the request's
                snapshot (-CurrentHash) -- otherwise the request closes as 'stale'. ok -> status 'approved'
                (the claim; the caller then writes the list and records 'applied' or 'failed').
      reject  : a SuperAdmin who is NOT the maker (the maker cancels instead).
      cancel  : the maker only.
      An expired request can never be approved (it closes as 'expired', whatever the decision).
      Role checks are the CALLER's (the Manager's SuperAdmin gate); this decides identity and state.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Request,
        [string]$RequestId,
        [Parameter(Mandatory)][string]$Actor,
        [Parameter(Mandatory)][ValidateSet('approve','reject','cancel')][string]$Decision,
        [string]$CurrentHash = '',
        [string]$Note = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $o = { param($ok, $code, $reason, $req) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req } }
    if ($null -eq $Request) { return (& $o $false 'not-found' 'there is no break-glass change request' $null) }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    if ("$RequestId".Trim() -and "$RequestId".Trim() -ne $r.id) {
        return (& $o $false 'wrong-request' ("request '{0}' is not the current break-glass change request ('{1}') -- reload" -f "$RequestId".Trim(), $r.id) $r)
    }
    if ($r.status -ne 'pending') { return (& $o $false 'not-pending' ("the request is already {0} -- only a pending request can be decided" -f $r.status) $r) }
    $now = $NowUtc.ToUniversalTime()
    $ex = Resolve-PimBreakGlassChangeExpiry -Request $r -NowUtc $now
    if ($ex.changed) { return (& $o $false 'expired' 'the request expired before a second SuperAdmin approved it -- raise a new request' $ex.request) }
    $isMaker = ((ConvertTo-PimBreakGlassIdentityKey -Identity $Actor) -eq (ConvertTo-PimBreakGlassIdentityKey -Identity $r.maker))
    $n = [ordered]@{}; foreach ($k in $r.Keys) { $n[$k] = $r[$k] }
    if ($Decision -eq 'cancel') {
        if (-not $isMaker) { return (& $o $false 'not-maker' ("only the maker ({0}) can cancel this request -- reject it instead" -f $r.maker) $r) }
        $n.status = 'cancelled'; $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o'); $n.closeNote = "$Note"
        return (& $o $true 'cancelled' 'request cancelled by its maker -- nothing was changed' $n)
    }
    if ($isMaker) {
        $what = if ($Decision -eq 'approve') { 'approve' } else { 'reject' }
        $alt = if ($Decision -eq 'approve') { 'another SuperAdmin must approve it' } else { 'cancel it instead' }
        return (& $o $false 'same-person' ("you raised this request, so you cannot {0} it -- {1}" -f $what, $alt) $r)
    }
    if ($Decision -eq 'reject') {
        $n.status = 'rejected'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o'); $n.closeNote = "$Note"
        return (& $o $true 'rejected' 'request rejected -- nothing was changed' $n)
    }
    # approve
    if ("$CurrentHash".Trim().ToLowerInvariant() -ne $r.snapshotHash) {
        $n.status = 'stale'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closedBy = "$Actor"; $n.closedUtc = $now.ToString('o')
        $n.closeNote = 'the list changed since the request was made'
        return (& $o $false 'stale' 'the list changed since the request was made -- raise a new request' $n)
    }
    $n.status = 'approved'; $n.checker = "$Actor"; $n.decidedUtc = $now.ToString('o'); $n.closeNote = "$Note"
    return (& $o $true 'approved' 'approved -- applying' $n)
}

function Get-PimBreakGlassCheckerCandidates {
    <#
      PURE. The SuperAdmins OTHER than the maker who could approve: SQL ManagerAccess entries with role
      SuperAdmin UNION env PIM_SuperAdmins (the two sources Get-PimManagerRole grants SuperAdmin from).
      Empty => the maker is the only SuperAdmin, so nobody can approve in the Manager and the operator
      route (tools/setup/Set-PimBreakGlassAccounts.ps1) is the way.
    #>
    param([AllowNull()][object]$AccessModel, [string]$EnvSuperAdmins = '', [string]$Maker = '')
    $ma = $AccessModel
    if ($ma -is [string]) { if ("$ma".Trim()) { try { $ma = "$ma" | ConvertFrom-Json } catch { $ma = $null } } else { $ma = $null } }
    $entries = @()
    if ($null -ne $ma) { $entries = @(if ($ma.PSObject.Properties['managerAccess']) { $ma.managerAccess } else { $ma }) }
    $supers = New-Object System.Collections.Generic.List[string]
    foreach ($e in $entries) {
        if ($null -eq $e) { continue }
        if ("$($e.role)".Trim() -ne 'SuperAdmin') { continue }
        $k = ConvertTo-PimBreakGlassIdentityKey -Identity "$($e.identity)"
        if ($k -and -not $supers.Contains($k)) { $supers.Add($k) }
    }
    foreach ($s in @("$EnvSuperAdmins" -split '[,;]+')) {
        $k = ConvertTo-PimBreakGlassIdentityKey -Identity $s
        if ($k -and -not $supers.Contains($k)) { $supers.Add($k) }
    }
    $mk = ConvertTo-PimBreakGlassIdentityKey -Identity $Maker
    return [string[]]@($supers.ToArray() | Where-Object { $_ -ne $mk })
}

# ---- store adapter (compare-and-set over pim.Settings) -----------------------------------------
function Assert-PimBreakGlassChangeStore {
    foreach ($c in @('Get-PimSqlSettingRaw', 'Set-PimSqlSettingIfUnchanged')) {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "the break-glass change store is unavailable: $c is not loaded (PIM v2 keeps the request in SQL only)" }
    }
}

function Get-PimBreakGlassChangeRecordRaw {
    # @{ raw = the stored text exactly (the compare-and-set token); request = the parsed record or $null }.
    param([Parameter(Mandatory)][string]$ConnectionString)
    Assert-PimBreakGlassChangeStore
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name (Get-PimBreakGlassChangeSettingName)
    return [pscustomobject]@{ raw = $raw; request = (ConvertTo-PimBreakGlassChangeRecord -Value $raw) }
}

function Save-PimBreakGlassChangeRecord {
    # Compare-and-set: write -Request only if the row is still -ExpectedRaw. $true = written, $false = lost a race.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Request, [AllowNull()][string]$ExpectedRaw)
    Assert-PimBreakGlassChangeStore
    $json = ConvertTo-PimBreakGlassChangeJson -Request $Request
    $n = Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name (Get-PimBreakGlassChangeSettingName) -NewValueJson $json -ExpectedValueJson $ExpectedRaw
    return ([int]$n -eq 1)
}

function Get-PimBreakGlassStoredListState {
    # The stored list (store row only) + its snapshot hash. THROWS when unreadable: a hash of "unknown" is
    # not the hash of an empty list, and a request raised or approved against it would be meaningless.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $s = Get-PimBreakGlassAccountStatus -ConnectionString $ConnectionString -NoCache
    if ($s.storeConfigured -and -not $s.storeOk) { throw "the break-glass list cannot be read: $($s.error)" }
    $acc = @($s.storeAccounts)
    return [pscustomobject]@{ accounts = $acc; hash = (Get-PimBreakGlassListHash -Accounts $acc) }
}

function Get-PimBreakGlassChangeRequest {
    <#
      The current request, with a lazy expiry: a pending request past its window is closed as 'expired'
      in the store (compare-and-set; losing the race is fine -- someone else moved it). Returns
      @{ request; expiredNow; open }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [datetime]$NowUtc = [datetime]::UtcNow)
    $rec = Get-PimBreakGlassChangeRecordRaw -ConnectionString $ConnectionString
    $ex = Resolve-PimBreakGlassChangeExpiry -Request $rec.request -NowUtc $NowUtc
    $expiredNow = $false
    if ($ex.changed) { $expiredNow = [bool](Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $ex.request -ExpectedRaw $rec.raw) }
    return [pscustomobject]@{ request = $ex.request; expiredNow = $expiredNow; open = (Test-PimBreakGlassChangeOpen -Request $ex.request -NowUtc $NowUtc) }
}

function New-PimBreakGlassChangeRequest {
    <#
      MAKER. Raise a pending request against the list stored NOW. Returns the Resolve-PimBreakGlassChangeCreate
      outcome (+ code 'conflict' when another request was written at the same moment, and 'base-changed'
      when -BaseHash -- the list the maker's screen showed -- is no longer the stored list).
      Nothing is written unless ok. THROWS on a store failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [AllowNull()][AllowEmptyCollection()][string[]]$Proposed,
        [Parameter(Mandatory)][string]$Maker,
        [string]$Justification = '',
        [switch]$ConfirmEmpty,
        [string]$BaseHash = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $state = Get-PimBreakGlassStoredListState -ConnectionString $ConnectionString
    if ("$BaseHash".Trim() -and "$BaseHash".Trim().ToLowerInvariant() -ne $state.hash) {
        return [pscustomobject]@{ ok = $false; code = 'base-changed'; reason = 'the break-glass list changed since you loaded it -- reload and make your change again'; request = $null; expiredPrevious = $null }
    }
    $rec = Get-PimBreakGlassChangeRecordRaw -ConnectionString $ConnectionString
    $res = Resolve-PimBreakGlassChangeCreate -Existing $rec.request -Current $state.accounts -Proposed $Proposed -Maker $Maker -Justification $Justification -ConfirmEmpty:$ConfirmEmpty -NowUtc $NowUtc
    if (-not $res.ok) { return $res }
    if (-not (Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $res.request -ExpectedRaw $rec.raw)) {
        return [pscustomobject]@{ ok = $false; code = 'conflict'; reason = 'another break-glass change request was raised at the same moment -- reload'; request = $null; expiredPrevious = $null }
    }
    return $res
}

function Close-PimBreakGlassChangeRequest {
    # REJECT (another SuperAdmin) or CANCEL (the maker). Returns the decision outcome; 'conflict' when the
    # request moved underneath. THROWS on a store failure.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$RequestId,
        [Parameter(Mandatory)][string]$Actor,
        [Parameter(Mandatory)][ValidateSet('reject','cancel')][string]$Decision,
        [string]$Note = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $rec = Get-PimBreakGlassChangeRecordRaw -ConnectionString $ConnectionString
    $res = Resolve-PimBreakGlassChangeDecision -Request $rec.request -RequestId $RequestId -Actor $Actor -Decision $Decision -Note $Note -NowUtc $NowUtc
    if ($res.ok -or $res.code -eq 'expired') {
        if (-not (Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $res.request -ExpectedRaw $rec.raw)) {
            return [pscustomobject]@{ ok = $false; code = 'conflict'; reason = 'the request changed while this was being recorded -- reload'; request = $rec.request }
        }
    }
    return $res
}

function Invoke-PimBreakGlassChangeApproval {
    <#
      CHECKER. Approve and APPLY. Order, and why:
        1. re-read the stored list and its hash, then decide (maker != checker, not expired, not stale);
           a stale request is CLOSED as stale (the list changed since the request was made);
        2. CLAIM the request (pending -> approved) with a compare-and-set -- so two approvals, or an
           approval racing the maker's cancel, cannot both win;
        3. write the list with Set-PimBreakGlassAccountList -ExpectedSnapshotHash (compare-and-set on the
           LIST row -- a write that raced in between the hash check and here is refused as stale);
        4. READ BACK and compare with the proposed list;
        5. close the request as 'applied' (or 'stale' / 'failed', with the reason).
      Returns @{ ok; code; reason; request; accounts(read back) }.
        code: applied | stale | failed | conflict | + every refusal code of Resolve-PimBreakGlassChangeDecision.
      THROWS only when the store cannot be read at all.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$RequestId,
        [Parameter(Mandatory)][string]$Checker,
        [string]$Note = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $mk = { param($ok, $code, $reason, $req, $acc) [pscustomobject]@{ ok = [bool]$ok; code = $code; reason = $reason; request = $req; accounts = @($acc) } }
    $state = Get-PimBreakGlassStoredListState -ConnectionString $ConnectionString
    $rec = Get-PimBreakGlassChangeRecordRaw -ConnectionString $ConnectionString
    $dec = Resolve-PimBreakGlassChangeDecision -Request $rec.request -RequestId $RequestId -Actor $Checker -Decision approve -CurrentHash $state.hash -Note $Note -NowUtc $NowUtc
    if (-not $dec.ok) {
        if ($dec.code -in @('stale', 'expired')) {
            [void](Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $dec.request -ExpectedRaw $rec.raw)
        }
        return (& $mk $false $dec.code $dec.reason $dec.request $state.accounts)
    }
    $claimJson = ConvertTo-PimBreakGlassChangeJson -Request $dec.request
    if (-not (Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $dec.request -ExpectedRaw $rec.raw)) {
        return (& $mk $false 'conflict' 'the request changed while it was being approved (a second approval, or the maker cancelled) -- reload' $rec.request $state.accounts)
    }
    $final = ConvertTo-PimBreakGlassChangeRecord -Value $dec.request
    $final.closedBy = "$Checker"; $final.closedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $code = 'applied'; $reason = ''; $readBack = @()
    try {
        [void](Set-PimBreakGlassAccountList -ConnectionString $ConnectionString -Accounts @($final.proposed) -ExpectedSnapshotHash $final.snapshotHash)
        $back = Get-PimBreakGlassStoredListState -ConnectionString $ConnectionString
        $readBack = @($back.accounts)
        if ($back.hash -ne (Get-PimBreakGlassListHash -Accounts $final.proposed)) {
            $code = 'failed'; $reason = 'the list was written but the read-back does not match the approved list -- check the Settings screen and the audit trail'
        } else {
            $reason = 'applied -- the Manager and the engine read the new list on their next check (within a minute)'
        }
    } catch {
        $m = "$($_.Exception.Message)"
        if ($m.StartsWith((Get-PimBreakGlassStaleMarker))) { $code = 'stale'; $reason = 'the list changed since the request was made -- raise a new request' }
        else { $code = 'failed'; $reason = "the list was NOT changed: $m" }
    }
    $final.status = $code
    if ($code -eq 'applied') { $final.applied = @($readBack) } else { $final.closeNote = $reason }
    $saved = Save-PimBreakGlassChangeRecord -ConnectionString $ConnectionString -Request $final -ExpectedRaw $claimJson
    if (-not $saved -and $code -eq 'applied') { $reason += ' (the request record could not be closed -- it still reads as approved)' }
    return (& $mk ($code -eq 'applied') $code $reason $final $readBack)
}
