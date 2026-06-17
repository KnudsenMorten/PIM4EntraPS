<#
  PIM4EntraPS -- approval-gated offboarding + revoke ENGINE (REQUIREMENTS §27 H3/H4).

  WHY THIS EXISTS (closes the incident gap)
  -----------------------------------------
  After the 2026-06-15 mass account-disable incident, AUTOMATIC offboarding was
  PROHIBITED (REQUIREMENTS §13): a date-driven / whole-population destructive pass
  must NEVER fire on its own. The catastrophe guards (PIM-DisableGuard: empty/unresolved
  desired abort + mass-disable circuit breaker) and the interim Manager revoke guard
  (#81: break-glass exclusion + count-confirm) are SAFETY NETS, not a control plane.

  This file is the missing control plane: a MAKER/CHECKER approval model so that a
  human REQUESTS a destructive identity action (offboard / revoke / disable), a
  DIFFERENT human APPROVES it, and only THEN may the guided sequence execute -- once.

    * Maker/checker queue: New-/Get-/Approve-/Deny-PimApprovalRequest. An approval
      record (requestor, action, target, justification, ticket, requested-at, status,
      approver, decided-at, decision-note). Persisted via the existing settings/SQL
      store (Set-PimSetting -> SQL pim.Settings; JSON-file fallback; in-mem last resort)
      -- the SAME store chain the scheduler uses, so it is shared hosted + local.

    * Offboarding-with-approval: Get-PimOffboardSequencePlan builds a guided sequence
      (disable -> revoke active -> schedule delete). Test-PimOffboardExecutionAllowed
      is the single gate the executor asks: it runs ONLY when an APPROVED request for
      that target exists -- and NEVER automatically. The DisableGuard circuit breaker
      + env-aware gate (Test-PimDisablePassAllowed) and the break-glass exclusion are
      composed in (NEVER bypassed): a maker/checker approval does not override them.

    * Revoke-with-approval: Test-PimRevokeApprovalRequired -- a revoke batch ABOVE the
      safety threshold (after break-glass exclusion) requires an APPROVED request.
      Small / break-glass-safe batches keep the interim #81 guard (count-confirm).
      Break-glass principals are ALWAYS excluded, approval or not.

  Maker != checker (separation of duties): the approver must differ from the requestor
  (Test-PimApprovalSeparationOk), unless an explicit self-approve allowance is set
  (operator policy; default OFF).

  Idempotent: an approved request executes ONCE. Approve-/Deny- only transition a
  PENDING request; re-deciding a decided request is a no-op (returns the prior result).
  Marking a request executed (Set-PimApprovalRequestExecuted) is the once-only latch.

  PURE decision functions + a thin persistence adapter (PS 5.1-safe: no ?./??,
  no ternary operator, null-guarded, .ToArray() not @() over List[object]).
#>

Set-StrictMode -Off

# ---- break-glass exclusion + interim revoke-guard plan (SHARED, engine-side) -
# These pure helpers were introduced for the interim #81 Manager revoke guard. They
# are defined HERE in engine/_shared so the ENGINE (which does not load the Manager)
# can reuse the SAME break-glass exclusion + count split. The Manager carries its own
# identical copies today; the serialized GUI-wiring pass will collapse the Manager
# onto these shared definitions. Defined only if not already present (idempotent;
# never clobbers a host that already provides them).
if (-not (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue)) {
    function Get-PimBreakGlassIdentifiers {
        # Break-glass / emergency principals to NEVER auto-revoke/offboard. Identifiers
        # may be UPNs and/or object (principal) ids; matching is case-insensitive.
        # Sourced from $global:PIM_BreakGlassAccounts (string[] or ';'/',' separated
        # string) or $env:PIM_BREAKGLASS_ACCOUNTS. Returns a lowercase string[].
        $raw = $global:PIM_BreakGlassAccounts
        if (-not $raw -and "$env:PIM_BREAKGLASS_ACCOUNTS") { $raw = "$env:PIM_BREAKGLASS_ACCOUNTS" }
        if (-not $raw) { return @() }
        $list = if ($raw -is [string]) { $raw -split '[;,]' } else { @($raw) }
        return @($list | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
}
if (-not (Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue)) {
    function Test-PimRowIsBreakGlass {
        # TRUE when the row's principalId/UPN/label matches a configured break-glass id.
        param([Parameter(Mandatory)]$Row, [string[]]$Identifiers)
        if (-not $Identifiers -or $Identifiers.Count -eq 0) { return $false }
        $cand = @()
        foreach ($k in 'principalId','principal','principalUpn','principalName','target','UserPrincipalName','Username') {
            $p = $Row.PSObject.Properties[$k]
            if ($p -and "$($p.Value)".Trim()) { $cand += "$($p.Value)".Trim().ToLowerInvariant() }
        }
        foreach ($c in $cand) { if ($Identifiers -contains $c) { return $true } }
        return $false
    }
}
if (-not (Get-Command Get-PimRevokeGuardPlan -ErrorAction SilentlyContinue)) {
    function Get-PimRevokeGuardPlan {
        # Pure what-if planner for a bulk revoke: split rows into {toRevoke,
        # skipped(break-glass)} + report whether a count-confirmation is required and
        # satisfied. No side effects. (Engine-side copy of the #81 Manager helper.)
        param([object[]]$Rows = @(), [int]$ConfirmThreshold = 5, [Nullable[int]]$ConfirmCount = $null)
        if ($ConfirmThreshold -lt 1) { $ConfirmThreshold = 1 }
        $bg = Get-PimBreakGlassIdentifiers
        $toRevoke = New-Object System.Collections.ArrayList
        $skipped  = New-Object System.Collections.ArrayList
        foreach ($r in $Rows) {
            if (-not $r) { continue }
            if (Test-PimRowIsBreakGlass -Row $r -Identifiers $bg) {
                [void]$skipped.Add([ordered]@{ id = "$($r.id)"; principal = "$($r.principal)"; type = "$($r.type)"; reason = 'break-glass account (protected)' })
            } else { [void]$toRevoke.Add($r) }
        }
        $count = $toRevoke.Count
        $confirmRequired = ($count -gt $ConfirmThreshold)
        $confirmSatisfied = if (-not $confirmRequired) { $true } elseif ($null -eq $ConfirmCount) { $false } else { [int]$ConfirmCount -eq $count }
        return [ordered]@{
            total = @($Rows | Where-Object { $_ }).Count
            toRevoke = $toRevoke.ToArray(); toRevokeCount = $count
            skipped = $skipped.ToArray(); skippedCount = $skipped.Count
            confirmThreshold = $ConfirmThreshold; confirmRequired = $confirmRequired; confirmSatisfied = $confirmSatisfied
        }
    }
}

# ---- constants ---------------------------------------------------------------
# Approval-request actions. offboard/revoke/disable are the destructive identity
# actions (s27 H3/H4). 'authoring' is the SECOND-PERSON gate on a SENSITIVE
# authoring/onboarding commit (s28 [M4]) -- a maker stages a privileged-role
# attach / guest-into-privileged-group / disable change, a different checker
# approves it before commit (see engine/_shared/PIM-SensitiveAuthoring.ps1).
$script:PimApprovalActions  = @('offboard','revoke','disable','authoring')
$script:PimApprovalStatuses = @('Pending','Approved','Denied','Executed','Expired')
# Where approval requests live in the settings/SQL store (one JSON blob: a list).
$script:PimApprovalSettingName = 'ApprovalRequests'

# ---- tunables ----------------------------------------------------------------
function Get-PimRevokeApprovalThreshold {
    # A revoke batch with MORE than this many (post-break-glass) rows needs an
    # APPROVED request. At/below it, the interim #81 count-confirm guard suffices.
    # Operator-tunable via $global:PIM_RevokeApprovalThreshold (default 5 -- matches
    # the #81 ConfirmThreshold / the DisableGuard absolute cap).
    $v = $global:PIM_RevokeApprovalThreshold
    if ($null -ne $v -and "$v" -match '^\d+$' -and [int]$v -ge 1) { return [int]$v }
    return 5
}

function Get-PimApprovalRequestTtlHours {
    # A PENDING request that is not decided within this many hours is EXPIRED (a stale
    # approval must not be executable forever). Operator-tunable; default 72h.
    $v = $global:PIM_ApprovalRequestTtlHours
    if ($null -ne $v -and "$v" -match '^\d+$' -and [int]$v -ge 1) { return [int]$v }
    return 72
}

function Test-PimApprovalSelfApproveAllowed {
    # Separation of duties: by default the approver MUST differ from the requestor.
    # An operator may relax this (single-operator lab / break-glass) via
    # $global:PIM_AllowSelfApprove. Default OFF (maker != checker enforced).
    [CmdletBinding()] param([object]$Override = $null)
    $val = $Override
    if ($null -eq $val) { $val = $global:PIM_AllowSelfApprove }
    if ($null -eq $val) { return $false }
    if ($val -is [bool]) { return [bool]$val }
    return ("$val".Trim().ToLowerInvariant() -in @('1','true','yes','y','on','enable','enabled'))
}

# ---- pure model --------------------------------------------------------------
function Test-PimApprovalAction {
    # Normalize + validate an action token. Returns the canonical action or $null.
    [CmdletBinding()] param([string]$Action)
    $a = "$Action".Trim().ToLowerInvariant()
    if ($a -in $script:PimApprovalActions) { return $a }
    return $null
}

function New-PimGateApprovalRequest {
    # Create a maker/checker approval-request record for a destructive identity action.
    # status starts Pending. Justification + Ticket are RECOMMENDED for audit (a blank
    # justification is allowed but flagged hasJustification=$false so policy can require it).
    #
    # NOTE (name-collision hardening): the GATE's internal callers (Add-PimApprovalRequest)
    # use THIS uniquely-named private builder, NOT the public alias below, so they keep
    # working even when the older portal lib (PIM-Approvals.ps1) shadows the public
    # New-PimApprovalRequest name (a different, assignment-request signature). Both libs
    # are dot-sourced by PIM-Functions.psm1 and Import-Module -Force can flip which public
    # definition wins; the gate must not depend on that.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Requestor,
        [Parameter(Mandatory)][string]$Action,    # offboard | revoke | disable
        [Parameter(Mandatory)][string]$Target,    # UPN / principalId / batch label
        [string]$Justification = '',
        [string]$Ticket = '',
        [object]$Detail = $null,                   # opaque: e.g. the revoke batch rows / offboard plan
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $act = Test-PimApprovalAction -Action $Action
    if (-not $act) { throw "New-PimApprovalRequest: unknown action '$Action' (expected one of: $($script:PimApprovalActions -join ', '))" }
    return [pscustomobject]@{
        id              = [guid]::NewGuid().ToString()
        requestor       = "$Requestor"
        action          = $act
        target          = "$Target"
        justification   = "$Justification"
        ticket          = "$Ticket"
        detail          = $Detail
        requestedUtc    = $NowUtc.ToUniversalTime().ToString('o')
        status          = 'Pending'
        approver        = ''
        decidedUtc      = ''
        decisionNote    = ''
        executedUtc     = ''
    }
}

function New-PimApprovalRequest {
    # PUBLIC alias of New-PimGateApprovalRequest (the gate's maker-record builder). Kept so
    # external callers / the offline gate test use the documented name. The gate's own
    # internal callers use the private New-PimGateApprovalRequest so they survive the older
    # portal lib (PIM-Approvals.ps1) shadowing this public name with a different signature.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Requestor,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$Justification = '',
        [string]$Ticket = '',
        [object]$Detail = $null,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    return (New-PimGateApprovalRequest -Requestor $Requestor -Action $Action -Target $Target -Justification $Justification -Ticket $Ticket -Detail $Detail -NowUtc $NowUtc)
}

function ConvertTo-PimGateUtc {
    # ROBUST timestamp -> [Nullable[datetime]] (UTC). Accepts an actual [datetime]
    # (the JSON store round-trips an ISO string back into a DateTime, whose default
    # ToString() is culture-formatted and does NOT round-trip through [datetime]::
    # TryParse -- that was silently making fresh persisted requests look "expired"),
    # OR a string parsed round-trip/invariant/assume-UTC. Returns $null when nothing
    # parses. PURE; PS 5.1-safe.
    [CmdletBinding()] param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt.ToUniversalTime() }
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::CurrentCulture, $styles, [ref]$dt)) { return $dt.ToUniversalTime() }
    return $null
}

function Test-PimApprovalRequestExpired {
    # PURE: is this PENDING request past its TTL as of NowUtc? Decided requests never
    # expire (their status is terminal). A request with an unparseable requestedUtc is
    # treated as expired (safe -- it cannot be executed).
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request, [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlHours = -1)
    if ("$($Request.status)" -ne 'Pending') { return $false }
    if ($TtlHours -lt 0) { $TtlHours = Get-PimApprovalRequestTtlHours }
    $req = ConvertTo-PimGateUtc -Value $Request.requestedUtc
    if ($null -eq $req) { return $true }
    return (($NowUtc.ToUniversalTime() - $req).TotalHours -ge $TtlHours)
}

function Test-PimApprovalSeparationOk {
    # Maker != checker. TRUE when the approver differs from the requestor (case-insensitive),
    # OR self-approve is explicitly allowed.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Requestor, [Parameter(Mandatory)][string]$Approver, [object]$AllowSelfApprove = $null)
    if (Test-PimApprovalSelfApproveAllowed -Override $AllowSelfApprove) { return $true }
    return ("$Requestor".Trim().ToLowerInvariant() -ne "$Approver".Trim().ToLowerInvariant())
}

function Resolve-PimGateApprovalDecision {
    # PURE maker/checker decision core (no persistence). Given a request + approver +
    # decision, return the NEW request object + an outcome.
    #   * Only a PENDING request may be decided. A re-decision of a decided request is a
    #     no-op (ok=$false, status unchanged, reason='already <status>').
    #   * approve requires separation of duties (maker != checker) unless allowed.
    #   * An expired pending request cannot be approved (auto-transitions to Expired).
    # Returns @{ ok; request(updated); status; reason }.
    #
    # NOTE (name-collision hardening): the gate's internal checker (Set-PimApprovalDecision)
    # calls THIS uniquely-named private core, NOT the public Resolve-PimApprovalDecision
    # alias below, so it survives the older portal lib (PIM-Approvals.ps1) shadowing that
    # public name with a different (-CanApprove) signature.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][string]$Approver,
        [Parameter(Mandatory)][ValidateSet('approve','deny')][string]$Decision,
        [string]$Note = '',
        [object]$AllowSelfApprove = $null,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$TtlHours = -1
    )
    $cur = "$($Request.status)"
    if ($cur -ne 'Pending') {
        return [pscustomobject]@{ ok = $false; request = $Request; status = $cur; reason = "request is already $cur (only a Pending request can be decided)" }
    }
    if (Test-PimApprovalRequestExpired -Request $Request -NowUtc $NowUtc -TtlHours $TtlHours) {
        $expired = $Request.PSObject.Copy()
        $expired.status = 'Expired'
        return [pscustomobject]@{ ok = $false; request = $expired; status = 'Expired'; reason = 'request expired before a decision was made' }
    }
    if ($Decision -eq 'approve' -and -not (Test-PimApprovalSeparationOk -Requestor "$($Request.requestor)" -Approver $Approver -AllowSelfApprove $AllowSelfApprove)) {
        return [pscustomobject]@{ ok = $false; request = $Request; status = 'Pending'; reason = "separation of duties: '$Approver' is the requestor and may not self-approve (set `$global:PIM_AllowSelfApprove to override)" }
    }
    $new = $Request.PSObject.Copy()
    $new.approver     = "$Approver"
    $new.decidedUtc   = $NowUtc.ToUniversalTime().ToString('o')
    $new.decisionNote = "$Note"
    $new.status       = if ($Decision -eq 'approve') { 'Approved' } else { 'Denied' }
    return [pscustomobject]@{ ok = $true; request = $new; status = "$($new.status)"; reason = "request $($new.status.ToLowerInvariant()) by $Approver" }
}

function Resolve-PimApprovalDecision {
    # PUBLIC alias of Resolve-PimGateApprovalDecision (the gate's pure decision core). Kept
    # under the documented name for external callers / the offline gate test; the gate's
    # internal checker uses the private core so it is immune to the portal-lib shadowing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][string]$Approver,
        [Parameter(Mandatory)][ValidateSet('approve','deny')][string]$Decision,
        [string]$Note = '',
        [object]$AllowSelfApprove = $null,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$TtlHours = -1
    )
    return (Resolve-PimGateApprovalDecision -Request $Request -Approver $Approver -Decision $Decision -Note $Note -AllowSelfApprove $AllowSelfApprove -NowUtc $NowUtc -TtlHours $TtlHours)
}

function Test-PimApprovalApprovedFor {
    # PURE: is there an APPROVED (not yet Executed, not Expired) request for this
    # action+target in the supplied request set, as of NowUtc? This is the predicate
    # the executor uses to know it MAY proceed. Returns the matching request or $null.
    # Target match is case-insensitive exact; action is normalized.
    [CmdletBinding()]
    param(
        [object[]]$Requests = @(),
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$TtlHours = -1
    )
    $act = Test-PimApprovalAction -Action $Action
    $tgt = "$Target".Trim().ToLowerInvariant()
    foreach ($r in @($Requests)) {
        if ($null -eq $r) { continue }
        if ("$($r.status)" -ne 'Approved') { continue }
        if ((Test-PimApprovalAction -Action "$($r.action)") -ne $act) { continue }
        if ("$($r.target)".Trim().ToLowerInvariant() -ne $tgt) { continue }
        # An Approved request whose original window already elapsed is NOT executable.
        # (Approved is terminal-positive, so Test-...Expired returns $false for it; we
        # re-check the decided age against TTL so a long-stale approval can't fire.)
        if ($TtlHours -lt 0) { $TtlHours = Get-PimApprovalRequestTtlHours }
        $dec = ConvertTo-PimGateUtc -Value $r.decidedUtc
        if ($null -ne $dec) {
            if (($NowUtc.ToUniversalTime() - $dec).TotalHours -ge $TtlHours) { continue }
        }
        return $r
    }
    return $null
}

# ---- persistence adapter (settings/SQL store; JSON-file + in-mem fallback) ---
# Mirrors PIM-Scheduler's run-history chain: prefer Set/Get-PimSetting (SQL
# pim.Settings when wired), else a JSON file, else in-process. PS 5.1 ConvertFrom-Json
# array-collapse is avoided via the temp-then-@() idiom.
$script:PimApprovalRequestsMem = $null

function Get-PimApprovalStorePath {
    # JSON fallback file path (used only when Set/Get-PimSetting is not loaded). Derived
    # from $global:PIM_ApprovalStatePath, else the scheduler state dir, else $env:TEMP.
    if ("$($global:PIM_ApprovalStatePath)".Trim()) { return "$($global:PIM_ApprovalStatePath)" }
    if ("$($global:PIM_SchedulerStatePath)".Trim()) {
        $dir = Split-Path -Parent $global:PIM_SchedulerStatePath
        if (-not $dir) { $dir = '.' }
        return (Join-Path $dir 'pim-approval-requests.json')
    }
    return (Join-Path $env:TEMP 'pim-approval-requests.json')
}

function Get-PimApprovalRequests {
    # All approval requests (newest first). Optional filters: -Status, -Action, -Target.
    [CmdletBinding()]
    param([string]$Status, [string]$Action, [string]$Target)
    $all = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name $script:PimApprovalSettingName; if ($v) { $tmp = if ($v -is [string]) { $v | ConvertFrom-Json } else { $v }; $all = @($tmp) } } catch {}
    }
    if ($null -eq $all) {
        $p = Get-PimApprovalStorePath
        if ($p -and (Test-Path -LiteralPath $p)) { try { $tmp = (Get-Content -LiteralPath $p -Raw -Encoding UTF8) | ConvertFrom-Json; $all = @($tmp) } catch {} }
    }
    if ($null -eq $all) { $all = @($script:PimApprovalRequestsMem) }
    $all = @(@($all) | Where-Object { $_ })
    if ("$Status".Trim()) { $all = @($all | Where-Object { "$($_.status)" -eq "$Status" }) }
    if ("$Action".Trim()) { $act = Test-PimApprovalAction -Action $Action; $all = @($all | Where-Object { (Test-PimApprovalAction -Action "$($_.action)") -eq $act }) }
    if ("$Target".Trim()) { $t = "$Target".Trim().ToLowerInvariant(); $all = @($all | Where-Object { "$($_.target)".Trim().ToLowerInvariant() -eq $t }) }
    return @($all | Sort-Object { "$($_.requestedUtc)" } -Descending)
}

function Save-PimApprovalRequests {
    # Persist the full request list via the same chain (SQL setting -> JSON file -> mem).
    [CmdletBinding()] param([object[]]$Requests = @())
    $script:PimApprovalRequestsMem = @($Requests)
    $json = (@($Requests) | ConvertTo-Json -Depth 12)
    if ($null -eq $json) { $json = '[]' }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { try { Set-PimSetting -Name $script:PimApprovalSettingName -Value $json | Out-Null; return } catch {} }
    $p = Get-PimApprovalStorePath
    if ($p) {
        $dir = Split-Path -Parent $p
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        try { Set-Content -LiteralPath $p -Value $json -Encoding UTF8 } catch {}
    }
}

function Add-PimApprovalRequest {
    # Create + persist a new Pending request. Returns the stored request object. This is
    # the "maker" entry point. Audited best-effort via Write-PimAuditEvent.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Requestor,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [string]$Justification = '',
        [string]$Ticket = '',
        [object]$Detail = $null,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $req = New-PimGateApprovalRequest -Requestor $Requestor -Action $Action -Target $Target -Justification $Justification -Ticket $Ticket -Detail $Detail -NowUtc $NowUtc
    $all = @(Get-PimApprovalRequests)
    Save-PimApprovalRequests -Requests (@($req) + $all)
    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action ("approval.request.created") -Target "$Target" -After @{ id = $req.id; action = $req.action; requestor = $Requestor; ticket = $Ticket } | Out-Null
        }
    } catch {}
    return $req
}

function Set-PimApprovalDecision {
    # The "checker" entry point: approve/deny a PENDING request BY ID, persisting the
    # transition. Idempotent -- re-deciding a decided request returns the prior outcome
    # without rewriting. Returns the Resolve-PimApprovalDecision outcome (with .request).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Approver,
        [Parameter(Mandatory)][ValidateSet('approve','deny')][string]$Decision,
        [string]$Note = '',
        [object]$AllowSelfApprove = $null,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $all = @(Get-PimApprovalRequests)
    $idx = -1
    for ($i = 0; $i -lt $all.Count; $i++) { if ("$($all[$i].id)" -eq "$Id") { $idx = $i; break } }
    if ($idx -lt 0) { return [pscustomobject]@{ ok = $false; request = $null; status = $null; reason = "no approval request with id '$Id'" } }
    $res = Resolve-PimGateApprovalDecision -Request $all[$idx] -Approver $Approver -Decision $Decision -Note $Note -AllowSelfApprove $AllowSelfApprove -NowUtc $NowUtc
    # Persist on a real transition (ok) OR when an expiry was detected (status flipped).
    if ($res.ok -or ("$($res.request.status)" -ne "$($all[$idx].status)")) {
        $all[$idx] = $res.request
        Save-PimApprovalRequests -Requests $all
        try {
            if ($res.ok -and (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue)) {
                Write-PimAuditEvent -Action ("approval.request." + $res.request.status.ToLowerInvariant()) -Target "$($res.request.target)" -After @{ id = $res.request.id; approver = $Approver; action = $res.request.action } | Out-Null
            }
        } catch {}
    }
    return $res
}

function Set-PimApprovalRequestExecuted {
    # ONCE-ONLY latch: mark an Approved request Executed so it can never drive a second
    # run. Returns @{ ok; request; reason }. Only an Approved request may be latched; a
    # second call is a no-op (ok=$false, reason='already executed').
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Id, [datetime]$NowUtc = [datetime]::UtcNow)
    $all = @(Get-PimApprovalRequests)
    $idx = -1
    for ($i = 0; $i -lt $all.Count; $i++) { if ("$($all[$i].id)" -eq "$Id") { $idx = $i; break } }
    if ($idx -lt 0) { return [pscustomobject]@{ ok = $false; request = $null; reason = "no approval request with id '$Id'" } }
    $r = $all[$idx]
    if ("$($r.status)" -eq 'Executed') { return [pscustomobject]@{ ok = $false; request = $r; reason = 'already executed (once-only)' } }
    if ("$($r.status)" -ne 'Approved') { return [pscustomobject]@{ ok = $false; request = $r; reason = "request is $($r.status), not Approved -- cannot execute" } }
    $new = $r.PSObject.Copy()
    $new.status = 'Executed'
    $new.executedUtc = $NowUtc.ToUniversalTime().ToString('o')
    $all[$idx] = $new
    Save-PimApprovalRequests -Requests $all
    try { if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { Write-PimAuditEvent -Action 'approval.request.executed' -Target "$($new.target)" -After @{ id = $new.id; action = $new.action } | Out-Null } } catch {}
    return [pscustomobject]@{ ok = $true; request = $new; reason = 'marked executed' }
}

# ---- OFFBOARDING-WITH-APPROVAL ----------------------------------------------
function Get-PimOffboardSequencePlan {
    # PURE: the guided offboard sequence for ONE target -- disable -> revoke active ->
    # schedule delete. Returns an ordered step list (each: order, step, description).
    # This is the PLAN only; nothing executes here. The delete step is SCHEDULED
    # (DeleteAfterDays from NowUtc), never immediate.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Target, [int]$DeleteAfterDays = 30, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($DeleteAfterDays -lt 0) { $DeleteAfterDays = 0 }
    $deleteOn = $NowUtc.ToUniversalTime().AddDays($DeleteAfterDays).ToString('yyyy-MM-dd')
    return @(
        [pscustomobject]@{ order = 1; step = 'disable';         target = "$Target"; description = "Set accountEnabled=`$false for $Target (sign-out everywhere)" }
        [pscustomobject]@{ order = 2; step = 'revoke-active';    target = "$Target"; description = "Revoke every active/eligible PIM activation + direct group membership for $Target" }
        [pscustomobject]@{ order = 3; step = 'schedule-delete';  target = "$Target"; description = "Schedule object delete for $deleteOn ($DeleteAfterDays day(s) after offboard)"; scheduledDeleteUtc = $deleteOn }
    )
}

function Test-PimOffboardExecutionAllowed {
    # THE GATE the offboard executor MUST call before doing anything destructive. An
    # offboard sequence runs ONLY when ALL hold (NONE may be bypassed):
    #   1. AUTOMATIC offboarding stays PROHIBITED -- this path is approval-driven, so an
    #      APPROVED, not-yet-executed, in-window request for action='offboard'+target
    #      MUST exist (Test-PimApprovalApprovedFor). No approval => not allowed, full stop.
    #      (A run with -Automatic set is REFUSED outright: automatic offboarding is never
    #      permitted, with or without an approval record.)
    #   2. The target is NOT a break-glass / emergency account (Test-PimRowIsBreakGlass
    #      on a synthetic row -- break-glass is excluded even WITH an approval).
    #   3. The DisableGuard composite still passes (Test-PimDisablePassAllowed): the
    #      desired set is positively resolved, the blast radius is within caps, and the
    #      account-disable capability is enabled for the environment. An approval does
    #      NOT override the circuit breaker.
    # Returns @{ allowed; reason; gate(<which failed>); approval(matched req or $null) }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [object[]]$Requests = @(),
        [switch]$Automatic,                         # an automatic/scan-driven invocation -> always refused
        [int]$ToDisable = 1,                        # blast radius for the DisableGuard composite
        [int]$Scanned = 1,
        [object[]]$Desired = @(),
        [Nullable[bool]]$DesiredResolved = $null,
        [object]$FeatureOverride = $null,
        [object]$AllowSelfApprove = $null,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    # GATE 0 -- automatic offboarding is PROHIBITED, unconditionally.
    if ($Automatic) {
        return [pscustomobject]@{ allowed = $false; gate = 'automatic-prohibited'; reason = 'automatic offboarding is PROHIBITED (REQUIREMENTS §13) -- offboarding may only run from an explicit, approved request'; approval = $null }
    }
    # GATE 1 -- an Approved request must exist.
    $appr = Test-PimApprovalApprovedFor -Requests $Requests -Action 'offboard' -Target $Target -NowUtc $NowUtc
    if (-not $appr) {
        return [pscustomobject]@{ allowed = $false; gate = 'no-approval'; reason = "no Approved (in-window, un-executed) offboard request for '$Target' -- maker/checker approval is required"; approval = $null }
    }
    # GATE 2 -- break-glass exclusion (never bypassed, even with approval).
    if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) {
        $bg = @(Get-PimBreakGlassIdentifiers)
        $row = [pscustomobject]@{ principalId = "$Target"; principal = "$Target"; principalUpn = "$Target"; principalName = "$Target" }
        if ((Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue) -and (Test-PimRowIsBreakGlass -Row $row -Identifiers $bg)) {
            return [pscustomobject]@{ allowed = $false; gate = 'break-glass'; reason = "'$Target' is a protected break-glass/emergency account -- excluded from offboarding"; approval = $appr }
        }
    }
    # GATE 3 -- the DisableGuard composite (circuit breaker / env / desired) -- NOT bypassed.
    if (Get-Command Test-PimDisablePassAllowed -ErrorAction SilentlyContinue) {
        $d = Test-PimDisablePassAllowed -ToDisable $ToDisable -Scanned $Scanned -Desired $Desired -DesiredResolved $DesiredResolved -FeatureOverride $FeatureOverride
        if (-not $d.allowed) {
            return [pscustomobject]@{ allowed = $false; gate = ("disable-guard:" + "$($d.tripped)"); reason = ("disable safety guard blocked the offboard: " + "$($d.reason)"); approval = $appr }
        }
    }
    return [pscustomobject]@{ allowed = $true; gate = $null; reason = 'approved + within all safety gates'; approval = $appr }
}

# ---- REVOKE-WITH-APPROVAL ----------------------------------------------------
function Test-PimRevokeApprovalRequired {
    # PURE: does this revoke batch need an APPROVED request? Compute the post-break-glass
    # to-revoke count (reusing the #81 Get-PimRevokeGuardPlan when present) and compare to
    # the approval threshold. Small / break-glass-only batches do NOT (the interim #81
    # count-confirm guard covers them). Returns @{ required; toRevokeCount; threshold;
    #   skippedCount }.
    [CmdletBinding()]
    param([object[]]$Rows = @(), [int]$Threshold = -1)
    if ($Threshold -lt 0) { $Threshold = Get-PimRevokeApprovalThreshold }
    $count = 0; $skipped = 0
    if (Get-Command Get-PimRevokeGuardPlan -ErrorAction SilentlyContinue) {
        $plan = Get-PimRevokeGuardPlan -Rows $Rows -ConfirmThreshold $Threshold
        $count = [int]$plan.toRevokeCount; $skipped = [int]$plan.skippedCount
    } else {
        # Fallback: exclude break-glass inline if the helper is loaded, else raw count.
        $bg = @(); if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) { $bg = @(Get-PimBreakGlassIdentifiers) }
        foreach ($r in @($Rows)) {
            if ($null -eq $r) { continue }
            if ((Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue) -and (Test-PimRowIsBreakGlass -Row $r -Identifiers $bg)) { $skipped++; continue }
            $count++
        }
    }
    return [pscustomobject]@{ required = ($count -gt $Threshold); toRevokeCount = $count; threshold = $Threshold; skippedCount = $skipped }
}

function Test-PimRevokeExecutionAllowed {
    # THE GATE the revoke executor calls before committing a bulk revoke. Decision:
    #   * Break-glass rows are ALWAYS excluded (reported in skipped) -- approval or not.
    #   * If the post-break-glass batch is AT/BELOW the approval threshold: allowed
    #     (the interim #81 count-confirm guard remains the operator's responsibility);
    #     gate='interim-guard'.
    #   * If ABOVE the threshold: allowed ONLY when an Approved (in-window, un-executed)
    #     request for action='revoke'+target exists; else blocked, gate='no-approval'.
    # Returns @{ allowed; gate; reason; required; toRevokeCount; threshold; skippedCount;
    #   approval }.
    [CmdletBinding()]
    param(
        [object[]]$Rows = @(),
        [Parameter(Mandatory)][string]$Target,        # batch label / scope the request was raised for
        [object[]]$Requests = @(),
        [int]$Threshold = -1,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $need = Test-PimRevokeApprovalRequired -Rows $Rows -Threshold $Threshold
    if (-not $need.required) {
        return [pscustomobject]@{ allowed = $true; gate = 'interim-guard'; reason = "batch of $($need.toRevokeCount) is at/below the approval threshold ($($need.threshold)); interim count-confirm guard applies"; required = $false; toRevokeCount = $need.toRevokeCount; threshold = $need.threshold; skippedCount = $need.skippedCount; approval = $null }
    }
    $appr = Test-PimApprovalApprovedFor -Requests $Requests -Action 'revoke' -Target $Target -NowUtc $NowUtc
    if (-not $appr) {
        return [pscustomobject]@{ allowed = $false; gate = 'no-approval'; reason = "batch of $($need.toRevokeCount) exceeds the approval threshold ($($need.threshold)); an Approved revoke request for '$Target' is required"; required = $true; toRevokeCount = $need.toRevokeCount; threshold = $need.threshold; skippedCount = $need.skippedCount; approval = $null }
    }
    return [pscustomobject]@{ allowed = $true; gate = 'approved'; reason = "batch of $($need.toRevokeCount) approved by $($appr.approver)"; required = $true; toRevokeCount = $need.toRevokeCount; threshold = $need.threshold; skippedCount = $need.skippedCount; approval = $appr }
}

# ---- OFFBOARD EXECUTOR (request -> approve -> EXECUTE; once-only) ------------
# This is the missing wiring half of REQUIREMENTS s27 [H4]: it connects an APPROVED
# offboard request to the EXISTING account-status-change pipeline. The decision of
# WHETHER it may run lives entirely in Test-PimOffboardExecutionAllowed (above) --
# this function NEVER re-implements a gate; it asks that one and refuses on any block.
#
# It executes the guided sequence (Get-PimOffboardSequencePlan: disable ->
# revoke-active -> schedule-delete) by routing the disable/revoke steps through
# Invoke-PimAccountStatusChange (the SAME pipeline the MSP kill-switch uses --
# disable=AccountStatus 'Disabled', revoke-active=AccountStatus 'Revoked'). The
# scheduled-delete step is recorded as a SCHEDULED intent only (never an immediate
# delete) -- it is staged for a later, separately-approved pass.
#
# The action invoker is INJECTABLE (-ActionInvoker) so the offline tests drive a
# MOCK and NEVER disable a real user; in the engine/Manager the default routes to
# the real Invoke-PimAccountStatusChange. On a successful run the Approved request
# is latched Executed (Set-PimApprovalRequestExecuted) so it can never drive a
# second run.

function Test-PimOffboardTargetIsBulk {
    # PURE: an offboard request targets exactly ONE principal. A blank/empty target,
    # or a target carrying a multi-principal separator (',' ';' newline / whitespace
    # run / a '*' wildcard / an 'all'/'everyone' keyword), is a BULK/empty target that
    # must NEVER auto-resolve into a population. The executor refuses these unless the
    # caller explicitly confirms (-ConfirmBulk) AND an approval exists -- bulk offboard
    # is never a one-click path. Returns @{ bulk; empty; reason }.
    [CmdletBinding()] param([AllowNull()][string]$Target)
    $t = "$Target".Trim()
    if (-not $t) { return [pscustomobject]@{ bulk = $true; empty = $true; reason = 'target is empty -- an empty offboard target must never resolve into a population' } }
    if ($t -match '[,;]' -or $t -match '\r|\n' -or $t -match '\s{2,}' -or $t -match '\*') {
        return [pscustomobject]@{ bulk = $true; empty = $false; reason = "target '$t' looks like a multi-principal / wildcard set -- bulk offboarding requires explicit confirmation + approval" }
    }
    if ($t.ToLowerInvariant() -in @('all','everyone','any','everybody')) {
        return [pscustomobject]@{ bulk = $true; empty = $false; reason = "target '$t' is a population keyword -- bulk offboarding requires explicit confirmation + approval" }
    }
    return [pscustomobject]@{ bulk = $false; empty = $false; reason = '' }
}

function Get-PimDefaultOffboardActionInvoker {
    # The default action invoker: route a sequence step through the EXISTING
    # account-status-change pipeline. Returns a scriptblock taking ($step,$target):
    #   step 'disable'         -> Invoke-PimAccountStatusChange ... -AccountStatus Disabled
    #   step 'revoke-active'   -> Invoke-PimAccountStatusChange ... -AccountStatus Revoked
    #   step 'schedule-delete' -> recorded as a scheduled intent (no immediate delete).
    # Each invocation returns @{ ok; detail }. NEVER called by the offline tests
    # (they inject their own mock) -- this is the live wiring only.
    return {
        param($Step, $Target)
        $s = "$($Step.step)".Trim().ToLowerInvariant()
        if ($s -eq 'schedule-delete') {
            return [pscustomobject]@{ ok = $true; detail = "delete SCHEDULED for $($Step.scheduledDeleteUtc) (not executed now)" }
        }
        if (-not (Get-Command Invoke-PimAccountStatusChange -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ ok = $false; detail = 'Invoke-PimAccountStatusChange pipeline not loaded' }
        }
        $status = if ($s -eq 'disable') { 'Disabled' } elseif ($s -eq 'revoke-active') { 'Revoked' } else { '' }
        if (-not $status) { return [pscustomobject]@{ ok = $false; detail = "unknown offboard step '$s'" } }
        try {
            Invoke-PimAccountStatusChange -UserPrincipalName "$Target" -AccountStatus $status | Out-Null
            return [pscustomobject]@{ ok = $true; detail = "$s via account-status pipeline (AccountStatus=$status)" }
        } catch {
            return [pscustomobject]@{ ok = $false; detail = "$s failed: $($_.Exception.Message)" }
        }
    }
}

function Invoke-PimOffboardExecution {
    # EXECUTE an APPROVED offboard request -- the once-only request -> approve ->
    # EXECUTE driver. The full decision (approval present, not automatic, break-glass
    # excluded, DisableGuard not bypassed, single-not-bulk target) is delegated to the
    # existing gates; this function executes ONLY when they all allow, runs the guided
    # sequence through the injectable action invoker, and latches the request Executed.
    #
    #   -RequestId     the Approved request to execute (resolved from the store).
    #   -Requests      (optional) the request set to gate against; defaults to the
    #                  persisted store (Get-PimApprovalRequests). Tests pass an explicit set.
    #   -ConfirmBulk   required to proceed on a bulk target (else refused; empty never runs).
    #   -ActionInvoker injectable { param($Step,$Target) -> @{ ok; detail } }; defaults
    #                  to the real account-status pipeline. Tests inject a MOCK so no
    #                  real user is ever disabled.
    #   -Automatic     refused outright (automatic offboarding is PROHIBITED).
    #   -DeleteAfterDays / -ToDisable / -Scanned / -Desired / -DesiredResolved /
    #   -FeatureOverride pass through to the plan + the DisableGuard composite.
    #
    # Returns @{ ok; gate; reason; executed; request; target; results[]; approval }.
    # Idempotent: a request already Executed (or not Approved) does not run; results=@().
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RequestId,
        [object[]]$Requests = $null,
        [switch]$ConfirmBulk,
        [scriptblock]$ActionInvoker = $null,
        [switch]$Automatic,
        [int]$DeleteAfterDays = 30,
        [int]$ToDisable = 1,
        [int]$Scanned = 1,
        [object[]]$Desired = @(),
        [Nullable[bool]]$DesiredResolved = $null,
        [object]$FeatureOverride = $null,
        [object]$AllowSelfApprove = $null,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    # Resolve the request set (explicit, else the persisted store).
    if ($null -eq $Requests) { $Requests = @(Get-PimApprovalRequests) }
    $reqList = @(@($Requests) | Where-Object { $_ })
    $rec = $null
    foreach ($r in $reqList) { if ("$($r.id)" -eq "$RequestId") { $rec = $r; break } }
    if ($null -eq $rec) {
        return [pscustomobject]@{ ok = $false; gate = 'not-found'; reason = "no approval request with id '$RequestId'"; executed = $false; request = $null; target = ''; results = @(); approval = $null }
    }
    if ((Test-PimApprovalAction -Action "$($rec.action)") -ne 'offboard') {
        return [pscustomobject]@{ ok = $false; gate = 'wrong-action'; reason = "request '$RequestId' is action '$($rec.action)', not 'offboard'"; executed = $false; request = $rec; target = "$($rec.target)"; results = @(); approval = $null }
    }
    $target = "$($rec.target)"

    # GUARD A -- single-not-bulk/empty. A bulk target needs explicit confirmation; an
    # empty target NEVER runs (even WITH -ConfirmBulk -- there is no population).
    $bulk = Test-PimOffboardTargetIsBulk -Target $target
    if ($bulk.empty) {
        return [pscustomobject]@{ ok = $false; gate = 'empty-target'; reason = $bulk.reason; executed = $false; request = $rec; target = $target; results = @(); approval = $null }
    }
    if ($bulk.bulk -and -not $ConfirmBulk) {
        return [pscustomobject]@{ ok = $false; gate = 'bulk-unconfirmed'; reason = $bulk.reason; executed = $false; request = $rec; target = $target; results = @(); approval = $null }
    }

    # GUARD B -- the composite execution gate (approval present + not automatic +
    # break-glass excluded + DisableGuard not bypassed). NEVER bypassed.
    $g = Test-PimOffboardExecutionAllowed -Target $target -Requests $reqList -Automatic:$Automatic `
            -ToDisable $ToDisable -Scanned $Scanned -Desired $Desired -DesiredResolved $DesiredResolved `
            -FeatureOverride $FeatureOverride -AllowSelfApprove $AllowSelfApprove -NowUtc $NowUtc
    if (-not $g.allowed) {
        return [pscustomobject]@{ ok = $false; gate = "$($g.gate)"; reason = "$($g.reason)"; executed = $false; request = $rec; target = $target; results = @(); approval = $g.approval }
    }

    # GUARD C -- once-only latch. Claim the request BEFORE executing so a concurrent
    # caller cannot double-run. Only an Approved request can be latched.
    $latch = Set-PimApprovalRequestExecuted -Id "$($rec.id)" -NowUtc $NowUtc
    if (-not $latch.ok) {
        return [pscustomobject]@{ ok = $false; gate = 'already-executed'; reason = "$($latch.reason)"; executed = $false; request = $latch.request; target = $target; results = @(); approval = $g.approval }
    }

    # EXECUTE the guided sequence through the (injectable) action invoker.
    if ($null -eq $ActionInvoker) { $ActionInvoker = Get-PimDefaultOffboardActionInvoker }
    $plan = @(Get-PimOffboardSequencePlan -Target $target -DeleteAfterDays $DeleteAfterDays -NowUtc $NowUtc)
    $results = New-Object System.Collections.ArrayList
    $allOk = $true
    foreach ($step in $plan) {
        $r = $null
        try { $r = & $ActionInvoker $step $target } catch { $r = [pscustomobject]@{ ok = $false; detail = "step '$($step.step)' threw: $($_.Exception.Message)" } }
        $stepOk = [bool]($r -and $r.ok)
        if (-not $stepOk) { $allOk = $false }
        [void]$results.Add([pscustomobject]@{ order = $step.order; step = "$($step.step)"; ok = $stepOk; detail = "$($r.detail)" })
    }

    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'offboard.executed' -Target $target -After @{ id = "$($rec.id)"; approver = "$($g.approval.approver)"; steps = $results.Count; allOk = $allOk } | Out-Null
        }
    } catch {}

    return [pscustomobject]@{
        ok       = $allOk
        gate     = 'executed'
        reason   = if ($allOk) { "offboard executed for $target ($($results.Count) step(s))" } else { "offboard executed for $target with one or more failed steps" }
        executed = $true
        request  = $latch.request
        target   = $target
        results  = $results.ToArray()
        approval = $g.approval
    }
}

# ---- REVOKE EXECUTOR (request -> approve -> EXECUTE; once-only) --------------
# This is the missing wiring half of REQUIREMENTS §28 [H3]: it connects an APPROVED
# over-threshold bulk-revoke request to the EXISTING active-assignment revoke pipeline.
# It is the EXACT mirror of Invoke-PimOffboardExecution: the decision of WHETHER a
# batch may run lives entirely in Test-PimRevokeExecutionAllowed (above) -- this
# function NEVER re-implements a gate; it asks that one and refuses on any block.
#
# WHAT-IF + break-glass exclusion + the count split are produced by the SHARED pure
# Get-PimRevokeGuardPlan (top of this file): break-glass principals are ALWAYS dropped
# from the executed set (reported in skipped), approval or not. ONLY the post-break-glass
# rows are revoked, and only when the gate allows. An over-threshold batch with NO
# Approved revoke request is REFUSED (gate=no-approval); an at/below-threshold batch
# runs under the interim #81 count-confirm guard (gate=interim-guard).
#
# The revoke invoker is INJECTABLE (-RevokeInvoker) so the offline tests drive a MOCK
# and NEVER revoke a real assignment; in the Manager the default routes to the real
# Invoke-PimActiveAssignmentRevokeBatch (provided by the Manager host -- this engine
# library does NOT define it). On a successful, over-threshold (approval-driven) run the
# Approved request is latched Executed (Set-PimApprovalRequestExecuted) so it can never
# drive a second run. (An interim-guard batch carries no approval to latch.)

function Get-PimDefaultRevokeInvoker {
    # The default revoke invoker: route the to-revoke rows through the EXISTING
    # active-assignment revoke batch the Manager provides. Returns a scriptblock
    # taking ($rows,$justification) and yielding the per-row result array. NEVER
    # called by the offline tests (they inject their own mock) -- live wiring only.
    return {
        param($Rows, $Justification)
        if (-not (Get-Command Invoke-PimActiveAssignmentRevokeBatch -ErrorAction SilentlyContinue)) {
            throw 'Invoke-PimActiveAssignmentRevokeBatch pipeline not loaded'
        }
        return @(Invoke-PimActiveAssignmentRevokeBatch -Rows @($Rows) -Justification "$Justification")
    }
}

function Invoke-PimRevokeExecution {
    # EXECUTE a bulk active-assignment revoke through the approval gate -- the mirror
    # of Invoke-PimOffboardExecution for the Maintenance bulk-revoke surface ([H3]).
    #
    # The full decision (break-glass excluded, whether an Approved request is required
    # for an over-threshold batch, whether one exists + is in-window) is delegated to
    # Test-PimRevokeExecutionAllowed -- this function NEVER bypasses it. It executes
    # ONLY the post-break-glass rows, ONLY when the gate allows, and -- when the batch
    # was over-threshold and thus approval-driven -- latches the Approved request
    # Executed (once-only) so it can never drive a second over-threshold run.
    #
    #   -Rows          the requested revoke rows (each: id, principal, principalId,
    #                  type, role, scope, ...). Break-glass rows are excluded by the gate.
    #   -Target        the batch label / scope the approval request was raised for.
    #   -Justification mandatory business reason recorded with every revoke (audit).
    #   -Requests      (optional) the request set to gate against; defaults to the
    #                  persisted store. Tests pass an explicit set.
    #   -RevokeInvoker injectable { param($Rows,$Justification) -> per-row results[] };
    #                  defaults to the real Invoke-PimActiveAssignmentRevokeBatch. Tests
    #                  inject a MOCK so no real assignment is ever revoked.
    #   -Threshold     the approval threshold (default -> Get-PimRevokeApprovalThreshold).
    #
    # Returns @{ ok; gate; reason; executed; required; toRevokeCount; threshold;
    #   skipped[]; skippedCount; results[]; approval; request }.
    # Idempotent for the approval-driven path: a request already Executed is refused at
    # the once-only latch (gate=already-executed) and nothing runs.
    [CmdletBinding()]
    param(
        [object[]]$Rows = @(),
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Justification,
        [object[]]$Requests = $null,
        [scriptblock]$RevokeInvoker = $null,
        [int]$Threshold = -1,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    # A revoke MUST carry a justification (audit) -- never an unattributed mass change.
    if ([string]::IsNullOrWhiteSpace($Justification)) {
        return [pscustomobject]@{ ok = $false; gate = 'no-justification'; reason = 'a justification is required for every bulk revoke'; executed = $false; required = $false; toRevokeCount = 0; threshold = (Get-PimRevokeApprovalThreshold); skipped = @(); skippedCount = 0; results = @(); approval = $null; request = $null }
    }
    $reqList = @(@(if ($null -eq $Requests) { Get-PimApprovalRequests } else { $Requests }) | Where-Object { $_ })

    # GATE A -- the composite revoke gate (break-glass split + approval-required +
    # Approved-request-present). NEVER bypassed. Decides allow/block + carries the plan.
    $g = Test-PimRevokeExecutionAllowed -Rows $Rows -Target $Target -Requests $reqList -Threshold $Threshold -NowUtc $NowUtc
    if (-not $g.allowed) {
        return [pscustomobject]@{ ok = $false; gate = "$($g.gate)"; reason = "$($g.reason)"; executed = $false; required = [bool]$g.required; toRevokeCount = [int]$g.toRevokeCount; threshold = [int]$g.threshold; skipped = @($g.skippedCount); skippedCount = [int]$g.skippedCount; results = @(); approval = $g.approval; request = $g.approval }
    }

    # Re-derive the post-break-glass to-revoke set + the skipped (break-glass) report
    # from the SAME shared planner the gate used, so we revoke EXACTLY what was gated.
    $plan = Get-PimRevokeGuardPlan -Rows $Rows -ConfirmThreshold ($g.threshold)
    $rowsToRevoke = @($plan.toRevoke)
    if ($rowsToRevoke.Count -eq 0) {
        # Everything selected was a protected break-glass account -- nothing to revoke.
        return [pscustomobject]@{ ok = $true; gate = 'all-break-glass'; reason = 'every selected assignment is a protected break-glass account; nothing revoked'; executed = $false; required = [bool]$g.required; toRevokeCount = 0; threshold = [int]$g.threshold; skipped = @($plan.skipped); skippedCount = [int]$plan.skippedCount; results = @(); approval = $g.approval; request = $g.approval }
    }

    # GATE B -- once-only latch (approval-driven path ONLY). Claim the Approved request
    # BEFORE executing so a concurrent caller cannot double-run an over-threshold batch.
    # An interim-guard (at/below threshold) batch carries no approval and is not latched.
    if ($g.approval -and "$($g.gate)" -eq 'approved') {
        $latch = Set-PimApprovalRequestExecuted -Id "$($g.approval.id)" -NowUtc $NowUtc
        if (-not $latch.ok) {
            return [pscustomobject]@{ ok = $false; gate = 'already-executed'; reason = "$($latch.reason)"; executed = $false; required = $true; toRevokeCount = [int]$plan.toRevokeCount; threshold = [int]$g.threshold; skipped = @($plan.skipped); skippedCount = [int]$plan.skippedCount; results = @(); approval = $latch.request; request = $latch.request }
        }
        $g.approval = $latch.request
    }

    # EXECUTE the post-break-glass rows through the (injectable) revoke invoker.
    if ($null -eq $RevokeInvoker) { $RevokeInvoker = Get-PimDefaultRevokeInvoker }
    $results = @()
    $execOk = $true
    try { $results = @(& $RevokeInvoker $rowsToRevoke $Justification) }
    catch { $execOk = $false; $results = @([pscustomobject]@{ id = $null; ok = $false; error = "revoke batch threw: $($_.Exception.Message)" }) }
    $okCount  = @($results | Where-Object { $_ -and $_.ok }).Count
    $errCount = @($results).Count - $okCount
    if ($errCount -gt 0) { $execOk = $false }

    try {
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'revoke.executed' -Target "$Target" -After @{ approver = "$($g.approval.approver)"; gate = "$($g.gate)"; revoked = $okCount; failed = $errCount; skipped = [int]$plan.skippedCount; justification = "$Justification" } | Out-Null
        }
    } catch {}

    return [pscustomobject]@{
        ok            = $execOk
        gate          = "$($g.gate)"
        reason        = if ($execOk) { "revoke executed for '$Target': $okCount revoked, $($plan.skippedCount) break-glass skipped" } else { "revoke executed for '$Target' with $errCount failed step(s)" }
        executed      = $true
        required      = [bool]$g.required
        toRevokeCount = [int]$plan.toRevokeCount
        threshold     = [int]$g.threshold
        skipped       = @($plan.skipped)
        skippedCount  = [int]$plan.skippedCount
        results       = @($results)
        approval      = $g.approval
        request       = $g.approval
    }
}
