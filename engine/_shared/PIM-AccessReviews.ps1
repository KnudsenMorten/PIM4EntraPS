# PIM4EntraPS -- Access Review OVERVIEW (read-only DATA/PROVIDER layer).
#
# Supplies the normalized, table-ready data the Manager's "Access Reviews" GUI tab
# will later render (the GUI tab is queued separately -- this file is data-only and
# touches NO html). It enumerates Entra Access Reviews that are relevant to the
# PIM-managed estate (the engine creates one access-review definition per opted-in
# group -- displayName "PIM4EntraPS review - <group>" -- see the AccessReviews
# provider in PIM-EngineProviders.ps1, order 80) and any other access-review
# definitions in the tenant, and returns one normalized row per review.
#
# Design tenets honoured (DESIGN §6/§7, REQUIREMENTS):
#   * READ-ONLY  -- list/get only. No POST/PATCH/DELETE; no review decisions are
#                   recorded or applied here. Strictly an overview.
#   * REST-first -- all Graph access goes through Invoke-PimGraph (PIM-Rest.ps1),
#                   app-only certificate auth, no Graph SDK unless
#                   $global:PIM_UseGraphSdk (honoured inside PIM-Rest, not here).
#   * Graceful   -- AccessReview.Read.All may not be granted yet; a 403/any error
#                   on the LIVE call is swallowed and an empty list returned (with a
#                   warning), never a crash. (The grant is in
#                   setup/Grant-PimGraphAppRoles.ps1.)
#   * PS 5.1-safe-- no ?./??/ternary; @() wraps WHOLE pipelines; null-tolerant prop
#                   reads; the NORMALIZER is PURE (offline-unit-testable, no network,
#                   no clock dependency beyond what the caller injects).
#
# Layout: small PURE shaping helpers (unit-tested offline) + one thin LIVE wrapper
# (Get-PimAccessReviewOverview) that fetches definitions/instances/decisions via
# Invoke-PimGraph and feeds the pure normalizer. Dot-sourced from PIM-Functions.psm1.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

function Get-PimArProp {
    # Null-tolerant property read off a Graph object (PSCustomObject or hashtable).
    # Returns the raw value (NOT stringified -- callers need ints/bools/objects too).
    param([object]$Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($n) -and $null -ne $Object[$n]) { return $Object[$n] }
        } else {
            $p = $Object.PSObject.Properties[$n]
            if ($p -and $null -ne $p.Value) { return $p.Value }
        }
    }
    return $null
}

function Get-PimAccessReviewScopeTarget {
    # Derive a human-readable scope/target ("Group: <id>", "Role: <id>", "<query>")
    # from an accessReviewScope object's query string. PURE.
    #   /groups/<id>/transitiveMembers           -> Group  <id>
    #   /roleManagement/directory/roleAssignment* -> Role   (directory roles)
    #   anything else                             -> the raw query
    param([object]$Scope)
    $query = "$(Get-PimArProp -Object $Scope -Names @('query'))"
    if (-not $query.Trim()) { return [pscustomobject]@{ kind = 'unknown'; id = ''; display = '(no scope)' } }
    if ($query -match '/groups/([^/]+)') {
        $gid = $Matches[1]
        return [pscustomobject]@{ kind = 'group'; id = $gid; display = "Group: $gid" }
    }
    if ($query -match '(?i)roleManagement|roleAssignment|directoryRoles') {
        # role-scoped review (scopeId on the query carries the roleDefinitionId)
        $rid = ''
        if ($query -match "roleDefinitionId\s+eq\s+'([^']+)'") { $rid = $Matches[1] }
        return [pscustomobject]@{ kind = 'role'; id = $rid; display = $(if ($rid) { "Role: $rid" } else { 'Directory role' }) }
    }
    return [pscustomobject]@{ kind = 'other'; id = ''; display = $query }
}

function ConvertTo-PimJsonArray {
    # Force a value into a real .NET array so it serializes as a JSON LIST -- even
    # when it holds exactly one element (PowerShell's ConvertTo-Json otherwise
    # collapses a single-element array to a scalar, which broke the GUI's
    # `.filter`/`.join` on r.Reviewers). $null -> empty array; a scalar -> a
    # single-element array; an array stays an array. PURE, PS 5.1-safe.
    #
    # NOTE: the Manager's default (compiled) JSON serializer keeps single-element
    # arrays as lists already; this guarantees the SAME shape on the ConvertTo-Json
    # fallback path (PS7 / serializer failure). Returned as [object[]] so callers /
    # the serializer always see an enumerable, never a bare string.
    param([object]$Value)
    if ($null -eq $Value) { return ,([object[]]@()) }
    # Strings are IEnumerable (of chars) -- treat as a single scalar item, not a sequence.
    if ($Value -is [string]) { return ,([object[]]@($Value)) }
    return ,([object[]]@($Value))
}

function Get-PimAccessReviewReviewers {
    # Flatten an accessReviewReviewerScope[] into a simple display list. Reviewers
    # are expressed as a query ("/users/<id>", "/groups/<id>", a managed-recurrence
    # special, or empty = "self/last-reviewer"). PURE.
    param([object[]]$Reviewers)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Reviewers)) {
        $q = "$(Get-PimArProp -Object $r -Names @('query'))"
        $qt = "$(Get-PimArProp -Object $r -Names @('queryType'))"
        if (-not $q.Trim()) { $out.Add('(self / specified-at-instance)'); continue }
        if ($q -match '/users/([^/]+)')  { $out.Add($Matches[1]); continue }
        if ($q -match '/groups/([^/]+)') { $out.Add("group:$($Matches[1])"); continue }
        $out.Add($(if ($qt) { "$qt`:$q" } else { $q }))
    }
    return $out.ToArray()
}

function Get-PimAccessReviewRecurrence {
    # Read the recurrence pattern off a definition's settings.recurrence and return
    # a friendly cadence string + isRecurring flag. PURE.
    param([object]$Settings)
    $rec = Get-PimArProp -Object $Settings -Names @('recurrence')
    if ($null -eq $rec) { return [pscustomobject]@{ isRecurring = $false; cadence = 'One-time' } }
    $pattern = Get-PimArProp -Object $rec -Names @('pattern')
    $range   = Get-PimArProp -Object $rec -Names @('range')
    $type    = "$(Get-PimArProp -Object $pattern -Names @('type'))"
    $interval = Get-PimArProp -Object $pattern -Names @('interval')
    if (-not $interval) { $interval = 1 }
    $rangeType = "$(Get-PimArProp -Object $range -Names @('type'))"
    # noEnd/endDate/numbered all count as recurring; absence of a pattern = one-time
    if (-not $type) { return [pscustomobject]@{ isRecurring = $false; cadence = 'One-time' } }
    $cadence = switch -Regex ($type) {
        '(?i)weekly'         { if ($interval -gt 1) { "Every $interval weeks" }  else { 'Weekly' };  break }
        '(?i)absoluteMonthly|relativeMonthly' {
            switch ([int]$interval) { 1 { 'Monthly' } 3 { 'Quarterly' } 6 { 'Semi-annually' } default { "Every $interval months" } }; break
        }
        '(?i)absoluteYearly|relativeYearly' { if ($interval -gt 1) { "Every $interval years" } else { 'Annually' }; break }
        '(?i)daily'          { if ($interval -gt 1) { "Every $interval days" } else { 'Daily' }; break }
        default              { "$type (interval $interval)" }
    }
    return [pscustomobject]@{ isRecurring = $true; cadence = $cadence; rangeType = $rangeType }
}

function Get-PimAccessReviewDecisionCounts {
    # Tally decision outcomes from an accessReviewInstanceDecisionItem[] (or any
    # array of objects carrying a `decision` field). PURE. Returns a fixed-shape
    # hashtable so the GUI always has the same columns.
    #   Graph decision values: NotReviewed | Approve | Deny | DontKnow | NotNotified
    param([object[]]$Decisions)
    $c = [ordered]@{ total = 0; pending = 0; approved = 0; denied = 0; dontKnow = 0 }
    foreach ($d in @($Decisions)) {
        $c.total++
        $val = "$(Get-PimArProp -Object $d -Names @('decision'))"
        switch -Regex ($val) {
            '(?i)^approve'       { $c.approved++; break }
            '(?i)^deny'          { $c.denied++;   break }
            '(?i)^dontknow'      { $c.dontKnow++; break }
            default              { $c.pending++ }   # NotReviewed / NotNotified / blank
        }
    }
    return $c
}

function ConvertTo-PimAccessReviewOverviewRow {
    # The single PURE normalizer: a Graph accessReview *definition* (optionally with
    # its current instance + that instance's decisions) -> ONE flat, table-ready row.
    # Stable, GUI-friendly shape -- direct table rendering, no further reshaping.
    param(
        [Parameter(Mandatory)][object]$Definition,
        [object]$CurrentInstance,
        [object[]]$Decisions
    )
    $name     = "$(Get-PimArProp -Object $Definition -Names @('displayName'))"
    $settings = Get-PimArProp -Object $Definition -Names @('settings')

    $scope    = Get-PimAccessReviewScopeTarget -Scope (Get-PimArProp -Object $Definition -Names @('scope'))
    $reviewers = Get-PimAccessReviewReviewers -Reviewers @(Get-PimArProp -Object $Definition -Names @('reviewers'))
    $recur    = Get-PimAccessReviewRecurrence -Settings $settings

    # status/dates come from the CURRENT instance when supplied, else the definition.
    $statusSrc = if ($CurrentInstance) { $CurrentInstance } else { $Definition }
    $status   = "$(Get-PimArProp -Object $statusSrc -Names @('status'))"
    $start    = "$(Get-PimArProp -Object $statusSrc -Names @('startDateTime'))"
    $due      = "$(Get-PimArProp -Object $statusSrc -Names @('endDateTime'))"

    $counts   = Get-PimAccessReviewDecisionCounts -Decisions @($Decisions)
    $autoApply = [bool](Get-PimArProp -Object $settings -Names @('autoApplyDecisionsEnabled'))

    # Is this an engine-managed PIM review? (displayName contract from the provider.)
    $managed  = ($name -like 'PIM4EntraPS review - *')
    $groupName = if ($managed) { ($name -replace '^PIM4EntraPS review - ', '') } else { '' }

    # Force Reviewers to a real array that survives BOTH PSCustomObject assignment
    # AND ConvertTo-Json (which collapses a 1-element array to a scalar). Holding the
    # comma-wrapped value in a local first, then assigning the property AFTER object
    # construction, prevents the hashtable-literal from unwrapping it -- so a lone
    # reviewer still serializes as ["x"], never "x" (the GUI dead-tab root cause).
    $reviewersArr = ConvertTo-PimJsonArray -Value $reviewers

    $row = [pscustomobject]@{
        Id              = "$(Get-PimArProp -Object $Definition -Names @('id'))"
        DisplayName     = $name
        IsPimManaged    = $managed
        GroupName       = $groupName            # engine-managed reviews only (else blank)
        ScopeKind       = $scope.kind           # group | role | other | unknown
        ScopeId         = $scope.id
        ScopeTarget     = $scope.display
        Reviewers       = $null                 # set below (array-preserving) -- see note above
        ReviewerCount   = @($reviewers).Count
        IsRecurring     = $recur.isRecurring
        Recurrence      = $recur.cadence
        Status          = $(if ($status) { $status } else { 'NotStarted' })
        StartDate       = $start
        DueDate         = $due
        AutoApply       = $autoApply
        DecisionsTotal  = $counts.total
        DecisionsPending = $counts.pending
        DecisionsApproved = $counts.approved
        DecisionsDenied = $counts.denied
        DecisionsDontKnow = $counts.dontKnow
    }
    $row.Reviewers = $reviewersArr
    return $row
}

# ---------------------------------------------------------------------------
# Live wrapper (the only network-touching part) -- READ-ONLY
# ---------------------------------------------------------------------------

function Get-PimAccessReviewOverview {
    <#
      .SYNOPSIS
        Read-only overview of Entra Access Reviews relevant to the PIM estate.
        Returns a normalized, table-ready row per review (see
        ConvertTo-PimAccessReviewOverviewRow). NO writes, NO decisions.
      .PARAMETER PimManagedOnly
        When set, returns only the engine-managed reviews (displayName
        "PIM4EntraPS review - *"); default returns ALL access-review definitions.
      .PARAMETER IncludeDecisionCounts
        When set, fetches the current instance's decision items per review to fill
        the Decisions* columns (extra GETs). Default OFF (lighter list).
      .NOTES
        REST-only via Invoke-PimGraph (cert app-only). Needs AccessReview.Read.All
        on the engine SPN; without it the LIVE call 403s -> warning + empty list
        (never a crash). The grant is in setup/Grant-PimGraphAppRoles.ps1.
    #>
    [CmdletBinding()]
    param(
        [switch]$PimManagedOnly,
        [switch]$IncludeDecisionCounts
    )
    $rows = New-Object System.Collections.Generic.List[object]
    $select = 'id,displayName,scope,reviewers,status,settings,createdDateTime'
    try {
        $defs = @(Invoke-PimGraph -All -Path "/identityGovernance/accessReviews/definitions?`$select=$select")
    } catch {
        Write-Warning "  [AccessReviewOverview] list definitions failed (need AccessReview.Read.All?): $($_.Exception.Message)"
        return @()
    }
    foreach ($def in $defs) {
        $name = "$(Get-PimArProp -Object $def -Names @('displayName'))"
        if ($PimManagedOnly -and ($name -notlike 'PIM4EntraPS review - *')) { continue }

        $instance  = $null
        $decisions = @()
        try {
            # Current instance = the most recent one (carries live status + dates).
            $did = "$(Get-PimArProp -Object $def -Names @('id'))"
            if ($did) {
                $inst = @(Invoke-PimGraph -Path ("/identityGovernance/accessReviews/definitions/$did/instances?`$orderby=startDateTime desc&`$top=1"))
                if ($inst.Count) {
                    $instance = $inst[0]
                    if ($IncludeDecisionCounts) {
                        $iid = "$(Get-PimArProp -Object $instance -Names @('id'))"
                        if ($iid) {
                            $decisions = @(Invoke-PimGraph -All -Path ("/identityGovernance/accessReviews/definitions/$did/instances/$iid/decisions?`$select=decision"))
                        }
                    }
                }
            }
        } catch {
            Write-Warning "  [AccessReviewOverview] instance/decision fetch failed for '$name': $($_.Exception.Message)"
        }
        $rows.Add((ConvertTo-PimAccessReviewOverviewRow -Definition $def -CurrentInstance $instance -Decisions $decisions))
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------------
# Seed / demo rows -- PURE, no network.
# ---------------------------------------------------------------------------
# These exercise the REAL normalizer (ConvertTo-PimAccessReviewOverviewRow) over
# Graph-accessReview-shaped fixtures, so the rows the Manager renders in seed mode
# have the IDENTICAL schema + go through the IDENTICAL scope/reviewer/recurrence/
# decision logic as a live tenant -- this is NOT a hand-built stub. It lets the
# "Access Reviews" GUI tab render meaningful content on a tenant where
# AccessReview.Read.All is not yet granted (live wrapper returns empty) or in an
# offline demo, without ever fabricating a row by hand.
function Get-PimAccessReviewSeedRows {
    [CmdletBinding()] param()
    # Fixture 1: engine-managed group review, recurring quarterly, in-progress,
    # with a realistic decision spread (mirrors a live group access review).
    $def1 = [pscustomobject]@{
        id = 'seed-def-1'
        displayName = 'PIM4EntraPS review - PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'
        scope = [pscustomobject]@{ query = '/groups/00000000-0000-0000-0000-000000000a01/transitiveMembers'; queryType = 'MicrosoftGraph' }
        reviewers = @([pscustomobject]@{ query = '/users/owner-alice'; queryType = 'MicrosoftGraph' })
        settings = [pscustomobject]@{
            autoApplyDecisionsEnabled = $false
            recurrence = [pscustomobject]@{ pattern = [pscustomobject]@{ type='absoluteMonthly'; interval=3 }; range = [pscustomobject]@{ type='noEnd' } }
        }
    }
    $inst1 = [pscustomobject]@{ id='seed-inst-1'; status='InProgress'; startDateTime='2026-06-01T00:00:00Z'; endDateTime='2026-06-21T00:00:00Z' }
    $dec1  = @(
        [pscustomobject]@{ decision='Approve' }; [pscustomobject]@{ decision='Approve' }
        [pscustomobject]@{ decision='Approve' }; [pscustomobject]@{ decision='Deny' }
        [pscustomobject]@{ decision='NotReviewed' }; [pscustomobject]@{ decision='NotReviewed' }
    )

    # Fixture 2: engine-managed group review, recurring monthly, completed.
    $def2 = [pscustomobject]@{
        id = 'seed-def-2'
        displayName = 'PIM4EntraPS review - PIM-Entra-ID-GroupsAdmin-L2-T1-CP-ID'
        scope = [pscustomobject]@{ query = '/groups/00000000-0000-0000-0000-000000000a02/transitiveMembers'; queryType = 'MicrosoftGraph' }
        reviewers = @(
            [pscustomobject]@{ query = '/users/owner-bob'; queryType = 'MicrosoftGraph' }
            [pscustomobject]@{ query = '/groups/reviewers-grp'; queryType = 'MicrosoftGraph' }
        )
        settings = [pscustomobject]@{
            autoApplyDecisionsEnabled = $true
            recurrence = [pscustomobject]@{ pattern = [pscustomobject]@{ type='absoluteMonthly'; interval=1 }; range = [pscustomobject]@{ type='noEnd' } }
        }
    }
    $inst2 = [pscustomobject]@{ id='seed-inst-2'; status='Completed'; startDateTime='2026-05-01T00:00:00Z'; endDateTime='2026-05-15T00:00:00Z' }
    $dec2  = @(
        [pscustomobject]@{ decision='Approve' }; [pscustomobject]@{ decision='Approve' }
        [pscustomobject]@{ decision='Deny' };    [pscustomobject]@{ decision='DontKnow' }
    )

    # Fixture 3: a role-scoped review, one-time, not started, no decisions yet.
    $def3 = [pscustomobject]@{
        id = 'seed-def-3'
        displayName = 'PIM4EntraPS review - PIM-Entra-ID-PrivRoleAdmin-L1-T0-CP-ID'
        scope = [pscustomobject]@{ query = "/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq 'e8611ab8-c189-46e8-94e1-60213ab1f814'" }
        reviewers = @([pscustomobject]@{ query = '' })   # self / specified-at-instance
        settings = [pscustomobject]@{ autoApplyDecisionsEnabled = $false }   # no recurrence -> One-time
    }

    # Fixture 4: a NON-PIM tenant review (so the operator sees other tenant reviews too).
    $def4 = [pscustomobject]@{
        id = 'seed-def-4'
        displayName = 'Quarterly guest-access review'
        scope = [pscustomobject]@{ query = '/groups/00000000-0000-0000-0000-000000000a04/transitiveMembers'; queryType = 'MicrosoftGraph' }
        reviewers = @([pscustomobject]@{ query = '/users/sec-team-lead'; queryType = 'MicrosoftGraph' })
        settings = [pscustomobject]@{
            autoApplyDecisionsEnabled = $false
            recurrence = [pscustomobject]@{ pattern = [pscustomobject]@{ type='absoluteMonthly'; interval=3 }; range = [pscustomobject]@{ type='noEnd' } }
        }
    }
    $inst4 = [pscustomobject]@{ id='seed-inst-4'; status='InProgress'; startDateTime='2026-06-10T00:00:00Z'; endDateTime='2026-06-30T00:00:00Z' }
    $dec4  = @([pscustomobject]@{ decision='NotReviewed' }; [pscustomobject]@{ decision='Approve' })

    $rows = New-Object System.Collections.Generic.List[object]
    $rows.Add((ConvertTo-PimAccessReviewOverviewRow -Definition $def1 -CurrentInstance $inst1 -Decisions $dec1))
    $rows.Add((ConvertTo-PimAccessReviewOverviewRow -Definition $def2 -CurrentInstance $inst2 -Decisions $dec2))
    $rows.Add((ConvertTo-PimAccessReviewOverviewRow -Definition $def3))
    $rows.Add((ConvertTo-PimAccessReviewOverviewRow -Definition $def4 -CurrentInstance $inst4 -Decisions $dec4))
    return $rows.ToArray()
}

# ===========================================================================
# ATTESTATION LAYER  (REQUIREMENTS § H7 -- per-item review DECISIONS, reviewer
# assignment + overdue surfacing, and an exportable evidence shape).
#
# This is the WRITE counterpart to the read-only overview above. Whereas the
# overview only LISTs reviews, this layer lets the engine RECORD a per-decision
# attestation outcome (approve / deny / recertify-as-dontKnow) against a Graph
# accessReview instance decision item, plus shape the reviewer-assignment /
# overdue / evidence data the GUI will render.
#
# Design tenets (mirror the overview's; DESIGN §6/§7, REQUIREMENTS):
#   * SAFE        -- every decision is EXPLICIT (one decision id at a time; NO
#                    bulk auto-approve helper exists here), IDEMPOTENT (re-PATCHing
#                    the same outcome is a no-op the API accepts), and AUDITED
#                    (the live wrapper returns an audit record; the engine's audit
#                    sink persists it -- this file does not write the trail itself).
#   * WRITE SCOPE -- recording decisions needs **AccessReview.ReadWrite.All** on
#                    the engine SPN (the read overview only needs
#                    AccessReview.Read.All). This file does NOT grant it; the grant
#                    is in setup/Grant-PimGraphAppRoles.ps1. Get-PimMissingRoleHint
#                    already maps a 403 on .../accessReviews → AccessReview.*.All.
#   * REST-first  -- all Graph writes go through Invoke-PimGraph (cert app-only).
#   * PS 5.1-safe -- no ?./??/ternary; @() wraps WHOLE pipelines; null-tolerant;
#                    the SHAPING helpers are PURE (offline-unit-testable, the clock
#                    is injected via -NowUtc, never read from the wall clock).
# ===========================================================================

# ---------------------------------------------------------------------------
# Pure attestation helpers
# ---------------------------------------------------------------------------

function Resolve-PimReviewDecisionValue {
    # Map a caller-supplied outcome (case-insensitive, friendly synonyms) to the
    # EXACT Graph accessReview decision token. PURE. Throws on an unknown outcome
    # (fail closed -- we never guess an attestation outcome).
    #   Approve  <- approve / approved / certify / recertify (keep access)
    #   Deny     <- deny / denied / reject / revoke / remove (remove access)
    #   DontKnow <- dontknow / dont-know / unsure / abstain  (needs more info)
    # NotReviewed is intentionally NOT writable here (it is the absence of a
    # decision, not an attestation a reviewer makes).
    param([Parameter(Mandatory)][string]$Outcome)
    switch -Regex ("$Outcome".Trim()) {
        '(?i)^(approve|approved|certif|recertif|keep|retain)' { return 'Approve' }
        '(?i)^(deny|denied|reject|revoke|remove)'             { return 'Deny' }
        '(?i)^(dont.?know|unsure|abstain|need)'               { return 'DontKnow' }
        default { throw "Resolve-PimReviewDecisionValue: unknown outcome '$Outcome' (expected Approve|Deny|DontKnow)" }
    }
}

function New-PimReviewDecisionPatch {
    # Build the EXACT PATCH body for a single accessReview decision item, plus the
    # audit record the engine persists. PURE -- no network, clock injected.
    # The Graph contract for recording one decision is:
    #   PATCH .../decisions/{decisionId}
    #   { "decision": "Approve|Deny|DontKnow", "justification": "<reason>" }
    # Justification is REQUIRED when the review's settings demand it; we always
    # send a non-empty one (fail-closed: an unjustified attestation is rejected).
    param(
        [Parameter(Mandatory)][string]$Outcome,
        [Parameter(Mandatory)][string]$Justification,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [string]$DecidedBy = ''
    )
    $val = Resolve-PimReviewDecisionValue -Outcome $Outcome
    $just = "$Justification".Trim()
    if (-not $just) { throw "New-PimReviewDecisionPatch: a non-empty -Justification is required (attestations must be justified)." }
    $body  = [ordered]@{ decision = $val; justification = $just }
    $audit = [pscustomobject]@{
        action        = 'access-review.decision'
        decision      = $val
        justification = $just
        decidedBy     = "$DecidedBy"
        decidedUtc    = $NowUtc.ToUniversalTime().ToString('o')
    }
    return [pscustomobject]@{ body = $body; audit = $audit }
}

function Test-PimReviewDecisionIdempotent {
    # Would re-recording $Outcome on a decision item whose CURRENT decision is
    # $Existing be a no-op? PURE. Used to skip a redundant PATCH (idempotency).
    # Only an IDENTICAL resolved outcome is idempotent; NotReviewed is never a
    # match (recording over it is a real change).
    param([Parameter(Mandatory)][string]$Outcome, [string]$Existing)
    $want = Resolve-PimReviewDecisionValue -Outcome $Outcome
    $have = "$Existing".Trim()
    if (-not $have) { return $false }
    if ($have -match '(?i)^notreviewed|^notnotified') { return $false }
    return ($have -ieq $want)
}

function Get-PimReviewItemDays {
    # Whole-days difference (DueUtc - NowUtc), positive = days remaining, negative
    # = days overdue. PURE. Blank/unparsable due -> $null. Clock injected.
    param([string]$DueDateTime, [datetime]$NowUtc = ([datetime]::UtcNow))
    $d = "$DueDateTime".Trim()
    if (-not $d) { return $null }
    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParse($d, [System.Globalization.CultureInfo]::InvariantCulture, `
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)
    if (-not $ok) { return $null }
    return [int][Math]::Floor((($parsed.ToUniversalTime()) - ($NowUtc.ToUniversalTime())).TotalDays)
}

function ConvertTo-PimReviewOverdueRow {
    # Shape ONE access-review instance into the overdue/expiry surfacing row the
    # GUI renders (a "what needs attention" list). PURE -- clock injected.
    #   * dueInDays  (+remaining / -overdue / $null=no due date)
    #   * isOverdue  (past due AND not completed)
    #   * isDueSoon  (within -SoonDays AND not overdue AND not completed)
    #   * pending    (decisions still NotReviewed -- the attestation backlog)
    #   * urgency    none|completed|dueSoon|overdue  (single field the GUI colours)
    param(
        [Parameter(Mandatory)][object]$Instance,
        [object]$Definition,
        [object[]]$Decisions,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int]$SoonDays = 3
    )
    $status = "$(Get-PimArProp -Object $Instance -Names @('status'))"
    $due    = "$(Get-PimArProp -Object $Instance -Names @('endDateTime'))"
    $start  = "$(Get-PimArProp -Object $Instance -Names @('startDateTime'))"
    $name   = "$(Get-PimArProp -Object $Definition -Names @('displayName'))"
    $counts = Get-PimAccessReviewDecisionCounts -Decisions @($Decisions)
    $days   = Get-PimReviewItemDays -DueDateTime $due -NowUtc $NowUtc
    $completed = ($status -match '(?i)^completed|^applied')
    $overdue = ($null -ne $days -and $days -lt 0 -and -not $completed)
    $dueSoon = ($null -ne $days -and $days -ge 0 -and $days -le $SoonDays -and -not $overdue -and -not $completed)
    $urgency = 'none'
    if ($completed)      { $urgency = 'completed' }
    elseif ($overdue)    { $urgency = 'overdue' }
    elseif ($dueSoon)    { $urgency = 'dueSoon' }
    $managed = ($name -like 'PIM4EntraPS review - *')
    return [pscustomobject]@{
        DefinitionId   = "$(Get-PimArProp -Object $Definition -Names @('id'))"
        InstanceId     = "$(Get-PimArProp -Object $Instance -Names @('id'))"
        DisplayName    = $name
        IsPimManaged   = $managed
        Status         = $(if ($status) { $status } else { 'NotStarted' })
        StartDate      = $start
        DueDate        = $due
        DueInDays      = $days
        IsOverdue      = $overdue
        IsDueSoon      = $dueSoon
        Urgency        = $urgency
        PendingCount   = $counts.pending
        DecisionsTotal = $counts.total
    }
}

function ConvertTo-PimReviewEvidenceItem {
    # Shape ONE decision item into an exportable EVIDENCE row (the per-principal
    # attestation record an auditor exports). PURE. Pulls the principal out of the
    # decision item's target/principal sub-object regardless of Graph casing.
    param([Parameter(Mandatory)][object]$DecisionItem)
    $principal = Get-PimArProp -Object $DecisionItem -Names @('principal','target')
    $resource  = Get-PimArProp -Object $DecisionItem -Names @('resource','accessReviewResource')
    $decision  = "$(Get-PimArProp -Object $DecisionItem -Names @('decision'))"
    $reviewedBy = Get-PimArProp -Object $DecisionItem -Names @('reviewedBy')
    return [pscustomobject]@{
        DecisionId      = "$(Get-PimArProp -Object $DecisionItem -Names @('id'))"
        PrincipalId     = "$(Get-PimArProp -Object $principal -Names @('id','userId','objectId'))"
        PrincipalName   = "$(Get-PimArProp -Object $principal -Names @('displayName','userPrincipalName'))"
        PrincipalUpn    = "$(Get-PimArProp -Object $principal -Names @('userPrincipalName'))"
        ResourceId      = "$(Get-PimArProp -Object $resource -Names @('id'))"
        ResourceName    = "$(Get-PimArProp -Object $resource -Names @('displayName'))"
        Decision        = $(if ($decision) { $decision } else { 'NotReviewed' })
        Justification   = "$(Get-PimArProp -Object $DecisionItem -Names @('justification'))"
        ReviewedBy      = "$(Get-PimArProp -Object $reviewedBy -Names @('displayName','userPrincipalName'))"
        ReviewedDateUtc = "$(Get-PimArProp -Object $DecisionItem -Names @('reviewedDateTime'))"
        Recommendation  = "$(Get-PimArProp -Object $DecisionItem -Names @('recommendation','accessRecommendation'))"
        AppliedResult   = "$(Get-PimArProp -Object $DecisionItem -Names @('applyResult'))"
    }
}

function ConvertTo-PimReviewEvidencePackage {
    # Assemble a full, exportable evidence PACKAGE for one review instance:
    # a header (who/what/when/scope) + the per-principal evidence items + a tally.
    # PURE -- this is the audit artefact the GUI exports (CSV/JSON) and an auditor
    # keeps. Clock injected (generatedUtc).
    param(
        [Parameter(Mandatory)][object]$Definition,
        [object]$Instance,
        [object[]]$Decisions,
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    $items = @(@($Decisions) | ForEach-Object { ConvertTo-PimReviewEvidenceItem -DecisionItem $_ })
    $counts = Get-PimAccessReviewDecisionCounts -Decisions @($Decisions)
    $name = "$(Get-PimArProp -Object $Definition -Names @('displayName'))"
    $scope = Get-PimAccessReviewScopeTarget -Scope (Get-PimArProp -Object $Definition -Names @('scope'))
    $statusSrc = if ($Instance) { $Instance } else { $Definition }
    $header = [pscustomobject]@{
        DefinitionId = "$(Get-PimArProp -Object $Definition -Names @('id'))"
        InstanceId   = "$(Get-PimArProp -Object $Instance -Names @('id'))"
        DisplayName  = $name
        IsPimManaged = ($name -like 'PIM4EntraPS review - *')
        ScopeKind    = $scope.kind
        ScopeTarget  = $scope.display
        Status       = "$(Get-PimArProp -Object $statusSrc -Names @('status'))"
        StartDate    = "$(Get-PimArProp -Object $statusSrc -Names @('startDateTime'))"
        DueDate      = "$(Get-PimArProp -Object $statusSrc -Names @('endDateTime'))"
        GeneratedUtc = $NowUtc.ToUniversalTime().ToString('o')
    }
    return [pscustomobject]@{
        Header  = $header
        Items   = $items
        Summary = [pscustomobject]@{
            Total    = $counts.total
            Approved = $counts.approved
            Denied   = $counts.denied
            DontKnow = $counts.dontKnow
            Pending  = $counts.pending
        }
    }
}

# ---------------------------------------------------------------------------
# Live attestation wrappers (the network-touching part) -- WRITE.
# Need AccessReview.ReadWrite.All on the engine SPN (NOT granted here).
# ---------------------------------------------------------------------------

function Set-PimAccessReviewDecision {
    <#
      .SYNOPSIS
        Record ONE attestation decision (Approve / Deny / DontKnow) against a single
        Graph accessReview instance decision item. EXPLICIT (one id), IDEMPOTENT
        (skips a redundant PATCH when the outcome already matches -- unless -Force),
        AUDITED (returns an audit record the caller persists).
      .PARAMETER Outcome
        Approve | Deny | DontKnow (friendly synonyms accepted, e.g. certify/revoke).
      .PARAMETER Justification
        Mandatory non-empty reason -- attestations must be justified.
      .NOTES
        Needs AccessReview.ReadWrite.All on the engine SPN. Without it the PATCH
        403s -> the missing-role hint (AccessReview.*.All + Grant-PimGraphAppRoles)
        is surfaced by Invoke-PimRest. There is deliberately NO bulk helper here;
        each decision is recorded individually (no auto-approve).
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][string]$DefinitionId,
        [Parameter(Mandatory)][string]$InstanceId,
        [Parameter(Mandatory)][string]$DecisionId,
        [Parameter(Mandatory)][string]$Outcome,
        [Parameter(Mandatory)][string]$Justification,
        [string]$DecidedBy = '',
        [switch]$Force
    )
    $patch = New-PimReviewDecisionPatch -Outcome $Outcome -Justification $Justification -NowUtc ([datetime]::UtcNow) -DecidedBy $DecidedBy
    $val = $patch.body.decision
    $base = "/identityGovernance/accessReviews/definitions/$DefinitionId/instances/$InstanceId/decisions/$DecisionId"

    # Idempotency: read the current decision; skip the PATCH if it already matches.
    if (-not $Force) {
        try {
            $cur = Invoke-PimGraph -Path "$base`?`$select=id,decision"
            $existing = "$(Get-PimArProp -Object $cur -Names @('decision'))"
            if (Test-PimReviewDecisionIdempotent -Outcome $val -Existing $existing) {
                Write-Verbose "  [AccessReviewDecision] $DecisionId already '$existing' -- no change."
                return [pscustomobject]@{ status = 'unchanged'; decision = $val; decisionId = $DecisionId; audit = $patch.audit }
            }
        } catch {
            Write-Warning "  [AccessReviewDecision] could not read current decision (continuing): $($_.Exception.Message)"
        }
    }

    if ($PSCmdlet.ShouldProcess($DecisionId, "Record access-review decision '$val'")) {
        Invoke-PimGraph -Method PATCH -Path $base -Body $patch.body | Out-Null
        return [pscustomobject]@{ status = 'recorded'; decision = $val; decisionId = $DecisionId; audit = $patch.audit }
    }
    return [pscustomobject]@{ status = 'skipped-whatif'; decision = $val; decisionId = $DecisionId; audit = $patch.audit }
}

function Get-PimAccessReviewOverdue {
    <#
      .SYNOPSIS
        Read-only surfacing of access-review instances that are OVERDUE or DUE SOON
        (the "needs attention" list the GUI renders). One ConvertTo-PimReviewOverdueRow
        per current instance. Read scope only (AccessReview.Read.All).
      .PARAMETER PimManagedOnly
        Limit to engine-managed reviews (displayName "PIM4EntraPS review - *").
      .PARAMETER SoonDays
        How many days ahead counts as "due soon" (default 3).
    #>
    [CmdletBinding()]
    param([switch]$PimManagedOnly, [int]$SoonDays = 3)
    $now = [datetime]::UtcNow
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $defs = @(Invoke-PimGraph -All -Path "/identityGovernance/accessReviews/definitions?`$select=id,displayName,scope,status,settings")
    } catch {
        Write-Warning "  [AccessReviewOverdue] list definitions failed (need AccessReview.Read.All?): $($_.Exception.Message)"
        return @()
    }
    foreach ($def in $defs) {
        $name = "$(Get-PimArProp -Object $def -Names @('displayName'))"
        if ($PimManagedOnly -and ($name -notlike 'PIM4EntraPS review - *')) { continue }
        $did = "$(Get-PimArProp -Object $def -Names @('id'))"
        if (-not $did) { continue }
        try {
            $inst = @(Invoke-PimGraph -Path ("/identityGovernance/accessReviews/definitions/$did/instances?`$orderby=startDateTime desc&`$top=1"))
            if (-not $inst.Count) { continue }
            $instance = $inst[0]
            $iid = "$(Get-PimArProp -Object $instance -Names @('id'))"
            $decisions = @()
            if ($iid) { $decisions = @(Invoke-PimGraph -All -Path ("/identityGovernance/accessReviews/definitions/$did/instances/$iid/decisions?`$select=decision")) }
            $rows.Add((ConvertTo-PimReviewOverdueRow -Instance $instance -Definition $def -Decisions $decisions -NowUtc $now -SoonDays $SoonDays))
        } catch {
            Write-Warning "  [AccessReviewOverdue] instance fetch failed for '$name': $($_.Exception.Message)"
        }
    }
    # Most urgent first: overdue, then dueSoon, then by soonest due date.
    $order = @{ overdue = 0; dueSoon = 1; none = 2; completed = 3 }
    return @($rows.ToArray() | Sort-Object @{ Expression = { $order["$($_.Urgency)"] } }, @{ Expression = { if ($null -eq $_.DueInDays) { [int]::MaxValue } else { $_.DueInDays } } })
}

function Get-PimAccessReviewEvidence {
    <#
      .SYNOPSIS
        Build the exportable EVIDENCE package for a review instance (header +
        per-principal decisions + tally) -- the audit artefact the GUI exports.
        Read scope only (AccessReview.Read.All). If -InstanceId is omitted the
        current (most recent) instance is used.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DefinitionId,
        [string]$InstanceId
    )
    $now = [datetime]::UtcNow
    try {
        $def = Invoke-PimGraph -Path "/identityGovernance/accessReviews/definitions/$DefinitionId`?`$select=id,displayName,scope,status,settings"
    } catch {
        Write-Warning "  [AccessReviewEvidence] get definition failed (need AccessReview.Read.All?): $($_.Exception.Message)"
        return $null
    }
    $iid = "$InstanceId".Trim()
    $instance = $null
    try {
        if (-not $iid) {
            $inst = @(Invoke-PimGraph -Path ("/identityGovernance/accessReviews/definitions/$DefinitionId/instances?`$orderby=startDateTime desc&`$top=1"))
            if ($inst.Count) { $instance = $inst[0]; $iid = "$(Get-PimArProp -Object $instance -Names @('id'))" }
        } else {
            $instance = Invoke-PimGraph -Path "/identityGovernance/accessReviews/definitions/$DefinitionId/instances/$iid"
        }
    } catch {
        Write-Warning "  [AccessReviewEvidence] instance fetch failed: $($_.Exception.Message)"
    }
    $decisions = @()
    if ($iid) {
        try { $decisions = @(Invoke-PimGraph -All -Path ("/identityGovernance/accessReviews/definitions/$DefinitionId/instances/$iid/decisions")) }
        catch { Write-Warning "  [AccessReviewEvidence] decisions fetch failed: $($_.Exception.Message)" }
    }
    return ConvertTo-PimReviewEvidencePackage -Definition $def -Instance $instance -Decisions $decisions -NowUtc $now
}

# ---------------------------------------------------------------------------
# Seed / demo -- PURE, no network. Exercises the REAL overdue + evidence
# shapers so the GUI's overdue list + evidence export render meaningful content
# offline / before AccessReview.* is granted (identical schema/logic to live).
# ---------------------------------------------------------------------------
function Get-PimAccessReviewAttestationSeed {
    # Returns @{ Overdue = <rows>; Evidence = <package> } against a fixed clock so
    # the offline demo is deterministic (an overdue review, a due-soon review, a
    # completed review, plus a full evidence package with mixed decisions).
    [CmdletBinding()] param([datetime]$NowUtc = ([datetime]'2026-06-15T00:00:00Z'))

    $defOverdue = [pscustomobject]@{ id='seed-def-1'; displayName='PIM4EntraPS review - PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'
        scope=[pscustomobject]@{ query='/groups/00000000-0000-0000-0000-000000000a01/transitiveMembers' }; settings=[pscustomobject]@{} }
    $instOverdue = [pscustomobject]@{ id='seed-inst-1'; status='InProgress'; startDateTime='2026-05-20T00:00:00Z'; endDateTime='2026-06-10T00:00:00Z' }
    $decOverdue  = @([pscustomobject]@{decision='Approve'};[pscustomobject]@{decision='NotReviewed'};[pscustomobject]@{decision='NotReviewed'})

    $defSoon = [pscustomobject]@{ id='seed-def-2'; displayName='PIM4EntraPS review - PIM-Entra-ID-GroupsAdmin-L2-T1-CP-ID'
        scope=[pscustomobject]@{ query='/groups/00000000-0000-0000-0000-000000000a02/transitiveMembers' }; settings=[pscustomobject]@{} }
    $instSoon = [pscustomobject]@{ id='seed-inst-2'; status='InProgress'; startDateTime='2026-06-01T00:00:00Z'; endDateTime='2026-06-17T00:00:00Z' }
    $decSoon  = @([pscustomobject]@{decision='Approve'};[pscustomobject]@{decision='Approve'};[pscustomobject]@{decision='NotReviewed'})

    $defDone = [pscustomobject]@{ id='seed-def-3'; displayName='Quarterly guest-access review'
        scope=[pscustomobject]@{ query='/groups/00000000-0000-0000-0000-000000000a03/transitiveMembers' }; settings=[pscustomobject]@{} }
    $instDone = [pscustomobject]@{ id='seed-inst-3'; status='Completed'; startDateTime='2026-05-01T00:00:00Z'; endDateTime='2026-05-15T00:00:00Z' }
    $decDone  = @([pscustomobject]@{decision='Approve'};[pscustomobject]@{decision='Deny'})

    $overdue = New-Object System.Collections.Generic.List[object]
    $overdue.Add((ConvertTo-PimReviewOverdueRow -Instance $instOverdue -Definition $defOverdue -Decisions $decOverdue -NowUtc $NowUtc))
    $overdue.Add((ConvertTo-PimReviewOverdueRow -Instance $instSoon    -Definition $defSoon    -Decisions $decSoon    -NowUtc $NowUtc))
    $overdue.Add((ConvertTo-PimReviewOverdueRow -Instance $instDone    -Definition $defDone    -Decisions $decDone    -NowUtc $NowUtc))

    # Evidence package fixture (mirrors a live decisions GET shape per principal).
    $evDecisions = @(
        [pscustomobject]@{ id='dec-1'; decision='Approve'; justification='Still required for daily ops'
            principal=[pscustomobject]@{ id='u1'; displayName='Alice Admin'; userPrincipalName='alice@contoso.test' }
            resource=[pscustomobject]@{ id='grp1'; displayName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID' }
            reviewedBy=[pscustomobject]@{ displayName='Owner One' }; reviewedDateTime='2026-06-12T09:00:00Z'; recommendation='Approve' }
        [pscustomobject]@{ id='dec-2'; decision='Deny'; justification='Left the team'
            principal=[pscustomobject]@{ id='u2'; displayName='Bob Builder'; userPrincipalName='bob@contoso.test' }
            resource=[pscustomobject]@{ id='grp1'; displayName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID' }
            reviewedBy=[pscustomobject]@{ displayName='Owner One' }; reviewedDateTime='2026-06-12T09:05:00Z'; recommendation='Deny' }
        [pscustomobject]@{ id='dec-3'; decision='NotReviewed'
            principal=[pscustomobject]@{ id='u3'; displayName='Carol Coder'; userPrincipalName='carol@contoso.test' }
            resource=[pscustomobject]@{ id='grp1'; displayName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID' }
            recommendation='Approve' }
    )
    $evidence = ConvertTo-PimReviewEvidencePackage -Definition $defOverdue -Instance $instOverdue -Decisions $evDecisions -NowUtc $NowUtc
    return [pscustomobject]@{ Overdue = $overdue.ToArray(); Evidence = $evidence }
}
