# =============================================================================
# PIM-DownlinkManager.ps1 -- the MANAGER-side glue for the MSP downlink surface
# (control #1/#2, framework MSP-2). Read the registry, compose the PURE plan over
# the SIGNED baseline, edit the per-relationship policy, and run a sync.
#
# 🔒 THE DECISION IS NEVER MADE HERE. Every view composes Get-PimDownlinkPlan, which
# verifies the signature and applies ring + policy itself. This file gathers facts and
# formats them for the GUI. If it formed its own opinion, the preview and the apply
# could disagree -- about who holds privilege in someone else's tenant.
#
# 🔴 THIS FILE READS AND PLANS. IT NEVER TOUCHES A MANAGED TENANT -- not to write, and
# not to read either. Two reasons, and the second one bites even if you accept the first:
#   * docs/REQUIREMENTS.md §22: "MSP never writes to a customer tenant; customer data
#     never leaves the tenant." Reaching in for a "harmless" read is the second half of
#     that sentence.
#   * A Manager in the MASTER holds the MASTER's ambient identity, and
#     Get-PimSqlConnectionString mints its Azure SQL token from it -- so any connection
#     aimed at a managed store authenticates as the WRONG tenant. It does not work, and
#     if it did it would be the master acting inside a customer.
#
# 📌 Under the agreed model (framework MSP-3) the managed tenant PULLS the signed
# baseline, decides locally with its own identity, and its own admin ACCEPTS before
# anything applies. So everything here is computed from the SIGNED BUNDLE plus the
# MASTER's own registry -- both of which the master legitimately holds.
#
# PS 5.1 COMPATIBLE: no ?./??, no ternary, Set-StrictMode -Off, null-guarded.
# =============================================================================

Set-StrictMode -Off

if ($PSScriptRoot) {
    if (-not (Get-Command Get-PimDownlinkPlan -ErrorAction SilentlyContinue)) {
        $__dl = Join-Path $PSScriptRoot 'PIM-Downlink.ps1'
        if (Test-Path -LiteralPath $__dl) { . $__dl }
    }
    if (-not (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        $__ss = Join-Path $PSScriptRoot 'PIM-SqlStore.ps1'
        if (Test-Path -LiteralPath $__ss) { . $__ss }
    }
}

# --- registry reads ----------------------------------------------------------

function Get-PimManagerDownlinkTenants {
    <#
      The managed relationships from the master registry. Returns @() when the
      platform schema is not applied -- a single-tenant deployment has no
      relationships, which is a legitimate empty answer, not an error.
    #>
    [CmdletBinding()] param([string]$ConnectionString)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    try {
        return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql @"
SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, DisplayName, Ring, Enabled
FROM platform.Tenants WHERE Enabled = 1 ORDER BY DisplayName
"@)
    } catch { return @() }
}

function Get-PimManagerDownlinkPolicy {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$TenantId, [string]$ConnectionString)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    try {
        return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Mode, GroupTag FROM pim.TenantRoleProjection WHERE TenantId = @t ORDER BY Mode, GroupTag" -Parameters @{ t = $TenantId } |
            ForEach-Object { [ordered]@{ Mode = "$($_.Mode)"; GroupTag = "$($_.GroupTag)" } })
    } catch { return @() }
}

function Set-PimManagerDownlinkPolicyMany {
    <#
      Replace the rule set for N relationships, IN ONE TRANSACTION.

      🔒 THE TRANSACTION IS THE WHOLE POINT, NOT TIDINESS. This is DELETE-then-INSERT, and
      "no rows for a tenant" is not a neutral state -- it means ALLOW ALL. So a failure
      between the delete and the last insert would leave the relationship projecting
      EVERYTHING the master publishes: an error that silently WIDENS privilege. That is
      ESTATE-14's failure class (an unchecked failure presented as a state of the world),
      and it is the reason this cannot be two separate statements.

      🔴 AND WHY *MANY*: the MSP-4 write is TAG-centric -- "this role reaches these 5 of 28"
      -- so one operator action edits up to 28 relationships. Committing them one at a time
      would let a failure at tenant 12 leave the estate half-narrowed, with no record of
      which half. Half a narrowing is not a smaller narrowing; it is an estate whose reach
      matches neither the old intent nor the new one, in tenants the operator does not own.

      Validation happens BEFORE any write for the same reason: a rule rejected halfway
      through would already have had its predecessors committed.

      -Edits: @( @{ TenantId; Rules = @( @{ Mode; GroupTag } ) } ). A tenant with an empty
      Rules list is reset to ALLOW ALL -- which is a widening, and therefore is exactly the
      case the caller must have decided deliberately.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Edits,
        [string]$ConnectionString,
        [string]$Note = 'set from the Manager'
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }

    # validate EVERY edit first -- nothing is written unless all of them are acceptable
    $clean = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Edits)) {
        $tid = "$(Get-PimDownlinkValue -Object $e -Key 'TenantId')".Trim()
        if (-not $tid) { throw "an edit is missing its TenantId (nothing was written)." }
        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(Get-PimDownlinkValue -Object $e -Key 'Rules')) {
            $m = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
            $g = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim()
            if ($m -notin @('allow','deny')) { throw "invalid Mode '$m' for tenant $tid -- must be allow or deny (nothing was written)." }
            if (-not $g) { throw "a rule for tenant $tid is missing its GroupTag (nothing was written)." }
            $rules.Add([ordered]@{ Mode = $m; GroupTag = $g }) | Out-Null
        }
        $clean.Add([ordered]@{ TenantId = $tid; Rules = @($rules.ToArray()) }) | Out-Null
    }
    if (-not $clean.Count) { return 0 }

    $cn = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $cn.Open()
        $tx = $cn.BeginTransaction()
        foreach ($e in $clean.ToArray()) {
            $del = $cn.CreateCommand(); $del.Transaction = $tx
            $del.CommandText = 'DELETE FROM pim.TenantRoleProjection WHERE TenantId = @t'
            [void]$del.Parameters.AddWithValue('@t', $e.TenantId)
            [void]$del.ExecuteNonQuery()
            foreach ($c in @($e.Rules)) {
                $ins = $cn.CreateCommand(); $ins.Transaction = $tx
                $ins.CommandText = 'INSERT INTO pim.TenantRoleProjection (TenantId, Mode, GroupTag, Notes) VALUES (@t, @m, @g, @n)'
                [void]$ins.Parameters.AddWithValue('@t', $e.TenantId)
                [void]$ins.Parameters.AddWithValue('@m', $c.Mode)
                [void]$ins.Parameters.AddWithValue('@g', $c.GroupTag)
                [void]$ins.Parameters.AddWithValue('@n', $Note)
                [void]$ins.ExecuteNonQuery()
            }
        }
        $tx.Commit(); $tx = $null
    } catch {
        if ($tx) { try { $tx.Rollback() } catch {} }
        throw "projection policy NOT changed (rolled back): $($_.Exception.Message)"
    } finally {
        try { $cn.Close() } catch {}
    }
    return $clean.Count
}

function Set-PimManagerDownlinkPolicy {
    <#
      Replace the rule set for ONE relationship. Full-set replace is correct here: the rows
      are scoped by TenantId so no other relationship is touched, and the GUI always submits
      the complete list it rendered.

      🔑 ONE WRITER, TWO ENTRY POINTS -- NOT TWO WRITERS. The tag-axis (MSP-4) and tenant-axis
      surfaces both narrow privilege in customer tenants, and the moment they have separate
      SQL the two can disagree about what "replace the rules" means, in the direction of
      widening. Session 32 escalated exactly this as a two-bad-options decision (duplicate it,
      or accept a weaker path) when the third option -- share it -- needed nobody's ruling.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$TenantId,
        [object[]]$Rules = @(),
        [string]$ConnectionString
    )
    [void](Set-PimManagerDownlinkPolicyMany -Edits @(,([ordered]@{ TenantId = $TenantId; Rules = @($Rules) })) -ConnectionString $ConnectionString)
}

# --- the baseline the plan is computed from ----------------------------------

function Get-PimManagerBaselineDoc {
    <#
      The signed bundle the Manager plans against. Preference order:
        1. an explicit -Path / $global:PIM_BaselineDocPath (a staged local document)
        2. $env:PIM_BaselineDocPath
      Returns @{ doc; source; error }. NEVER fabricates a document -- a missing
      baseline is reported, because planning without one would report "nothing
      projects", which is indistinguishable from a correct empty answer.
    #>
    [CmdletBinding()] param([string]$Path)
    if (-not $Path) { $Path = "$($global:PIM_BaselineDocPath)" }
    if (-not $Path) { $Path = "$($env:PIM_BaselineDocPath)" }
    if (-not "$Path".Trim()) { return @{ doc = $null; source = ''; error = 'no baseline document configured (set PIM_BaselineDocPath to the signed bundle the master publishes)' } }
    if (-not (Test-Path -LiteralPath $Path)) { return @{ doc = $null; source = "$Path"; error = "baseline document not found at $Path" } }
    try {
        $doc = (Get-Content -LiteralPath $Path -Raw) | ConvertFrom-Json
        return @{ doc = $doc; source = "$Path"; error = '' }
    } catch { return @{ doc = $null; source = "$Path"; error = "baseline document is not valid JSON: $($_.Exception.Message)" } }
}

# --- the GUI payload ---------------------------------------------------------

function Get-PimManagerDownlinkOverview {
    <#
      Everything /api/downlink renders: one entry per managed relationship, each
      carrying the PURE plan's own projected / excluded / unresolved lists (with the
      reason strings the core produced) plus the groups it would create vs defer.
    #>
    [CmdletBinding()] param([string]$ConnectionString, [string]$BaselinePath)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $canWrite = $true
    if (Get-Command Test-PimManagerRoleAtLeast -ErrorAction SilentlyContinue) {
        try { $canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $canWrite = $false }
    }
    $tenants = @(Get-PimManagerDownlinkTenants -ConnectionString $ConnectionString)
    $bl = Get-PimManagerBaselineDoc -Path $BaselinePath

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in $tenants) {
        $tid = "$($t.TenantId)"
        $entry = [ordered]@{
            tenantId       = $tid
            name           = "$($t.DisplayName)"
            ring           = [int]("0" + "$($t.Ring)")
            adminCount     = 0
            projected      = @(); excluded = @(); unresolved = @()
            # 🔴 THESE TWO WERE COMPUTED BY THE PLAN AND THROWN AWAY HERE, AND THAT MADE A REAL
            # NARROWING INVISIBLE. A role narrowed by its `Target` selector never reaches
            # projected/excluded/unresolved at all -- it is filtered out UPSTREAM of the projection
            # -- so the tenant appeared in NEITHER the reaches list NOR the withheld list. The
            # reach view's own contract is "four narrowings, kept apart, each with its own fix",
            # and two of the four could not be seen from the surface that promises them.
            # 🪤 It fails the quiet way: no error, no empty state, just a tenant that is absent.
            notTargeted    = @(); classHeld = @()
            groupsToCreate = @(); groupsDeferred = @()
            policy         = @(Get-PimManagerDownlinkPolicy -TenantId $tid -ConnectionString $ConnectionString)
            error          = ''
        }
        if (-not $bl.doc) { $entry.error = $bl.error }
        else {
            try {
                # 🔴 NO -SlaveGroupTags, ON PURPOSE. Knowing which tags the customer already
                # owns would mean READING THEIR STORE, and §22 is explicit that customer data
                # never leaves their tenant -- a "harmless" read is still a reach-in. It also
                # could not work: the master's ambient identity has no rights there.
                # Omitting it makes the plan treat every tag the bundle defines as creatable,
                # which is the honest MASTER-SIDE view: "this is what we would OFFER". Which
                # of those the customer already owns is resolved by the customer, when they
                # pull -- and that is exactly where MSP-3 puts the decision.
                # 🔴 NOT $env:TEMP -- unset in the Linux container this runs in. It would not throw
                # here (an empty LocalRoot is handled), which is worse: the plan would quietly
                # stage nothing and report a reason nobody reads.
                $planArgs = @{
                    Scenario = 'S6'; Doc = $bl.doc; TenantId = $tid
                    SlaveRing = $entry.ring; LocalRoot = [System.IO.Path]::GetTempPath()
                }
                $plan = Get-PimDownlinkPlan @planArgs
                if (-not $plan.ok) { $entry.error = "$($plan.reason)" }
                else {
                    $entry.adminCount = @($plan.admins).Count
                    $entry.notTargeted = @($plan.notTargeted)
                    $entry.classHeld   = @($plan.classHeld)
                    if ($plan.projection) {
                        $entry.projected  = @($plan.projection.projected)
                        $entry.excluded   = @($plan.projection.excluded)
                        $entry.unresolved = @($plan.projection.unresolved)
                    }
                    if ($plan.definitions) {
                        $entry.groupsToCreate = @(@($plan.definitions.create) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
                        $entry.groupsDeferred = @(@($plan.definitions.defer)  | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
                    }
                }
            } catch { $entry.error = "plan failed: $($_.Exception.Message)" }
        }
        $out.Add($entry) | Out-Null
    }

    $blInfo = $null
    if ($bl.doc) {
        $ver = 0
        try {
            $p = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($bl.doc.payloadB64)")) | ConvertFrom-Json
            $ver = $p.version
        } catch {}
        # 🪤 `verified` must reflect a REAL verification, not the fact that a file parsed.
        # It was hardcoded $true, so a bundle with a broken signature still showed
        # "signature verified" in the banner while every relationship below it carried a
        # refusal. Derive it from an ACTUAL verify of the document.
        $ok = $false
        try { if (Get-Command Test-PimDownlinkBaseline -ErrorAction SilentlyContinue) { $ok = [bool](Test-PimDownlinkBaseline -Doc $bl.doc).ok } } catch { $ok = $false }
        $blInfo = [ordered]@{ version = $ver; source = "$($bl.source)"; verified = $ok }
    }
    return [ordered]@{
        relationships = @($out.ToArray())
        baseline      = $blInfo
        canWrite      = $canWrite
        reason        = $(if (-not $tenants.Count) { 'No managed tenants are registered in platform.Tenants.' } elseif (-not $bl.doc) { "$($bl.error)" } else { '' })
    }
}

function Get-PimProjectionWithholdAxis {
    <#
      WHICH narrowing held a tag back, as a FIELD -- classified once, here.

      🔑 PROSE PROTECTS A HUMAN READING A LOG; A FIELD PROTECTS THE NEXT COMPONENT. The plan has
      always produced a good English reason, and the reach view rendered it. But the WRITE half
      (MSP-4 authoring) has to make a decision on it -- "can a policy edit actually deliver the
      reach you asked for?" -- and a decision keyed on a sentence breaks the day somebody improves
      the sentence. Session 31 learned this on `retracts`; this is the same lesson, one surface on.

      Returns: targeting | policy | ring | unresolved | capability | other.
      🔒 `other` IS THE FAIL-CLOSED ANSWER and it is deliberately not called 'unknown-but-probably-
      policy'. The write path refuses to promise a grant it cannot classify, because the failure it
      is avoiding is reporting privilege as granted in a customer tenant when it was not.
    #>
    [CmdletBinding()] param([string]$Bucket, [string]$Reason)
    $b = "$Bucket".Trim().ToLowerInvariant()
    # The bucket is stronger evidence than the prose, so it is read first: a row that arrived in
    # the notTargeted list IS a targeting narrowing whatever its message says.
    if ($b -eq 'unresolved')  { return 'unresolved' }
    if ($b -eq 'nottargeted') { return 'targeting' }
    if ($b -eq 'classheld')   { return 'capability' }
    # 🪤 `.Contains()`, NOT `-like`/`-match`: reason strings carry '[' and ']' (and a stray '*'
    # from a deny pattern), which -like reads as a character class. That trap cost a run in
    # session 32 and it is one line away from here.
    $r = "$Reason".ToLowerInvariant()
    if ($r.Contains('not targeted') -or $r.Contains('target selector')) { return 'targeting' }
    if ($r.Contains('blocked'))          { return 'capability' }
    if ($r.Contains("tenant's ring"))    { return 'ring' }
    if ($r.Contains('relationship policy') -or $r.Contains('allow-list')) { return 'policy' }
    return 'other'
}

function Get-PimProjectionReach {
    <#
      MSP-4 -- THE SURFACE. Pure.

      🔑 THE OPERATOR'S QUESTION IS THE INVERSE OF THE ONE THE MANAGER COULD ALREADY ANSWER.
      `/api/downlink` is TENANT-centric: pick a relationship, see what it gets. The ask -- *"this
      role goes to only 5 of 28 tenants"* -- is ARTIFACT-centric: pick a role, see which tenants it
      reaches. Same data, transposed, and the transpose is the whole feature: nobody can audit
      "5 of 28" by opening 28 tabs and remembering.

      🪤 AND WITHOUT IT, NARROWING IS UNVERIFIABLE IN THE DIRECTION THAT MATTERS. Every narrowing
      axis works and is tested, but the only way to see the RESULT was to read hand-written SQL
      against `pim.TenantRoleProjection` and a `Target` column, per tenant, and hold the answer in
      your head. A control you cannot audit is a control you cannot trust -- and this one grants
      privilege in tenants the operator does not own.

      Returns one entry per GROUP TAG: which tenants it reaches, which it does not, and WHY NOT --
      distinguishing the four narrowings the plan already keeps separate, because collapsing them
      is what makes "why did this role not arrive" unanswerable:
        * `targeting`  -- the artifact's own Target selector never offered it to this tenant
        * `policy`     -- the relationship's allow/deny rules excluded it
        * `ring`       -- the admin holding it sits above the tenant's ring
        * `unresolved` -- offered, but the tenant has no group for that tag
      PURE: takes the already-computed per-tenant overview entries; no SQL, no network. That keeps
      the transpose testable offline and means it can never disagree with the per-tenant view --
      it is literally the same numbers, rotated.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Relationships)

    # 🔴 THE UNIT OF THIS VIEW IS A TENANT, NOT AN ASSIGNMENT ROW -- and the first version counted
    # rows. `projected` carries one row per (admin, tag), so a tenant where TWO admins hold the
    # same role was added TWICE, and the operator's headline sentence read "2 of 2 tenant(s),
    # not narrowed" for an estate where the truth was "1 of 2, NARROWED". Measured, not reasoned.
    # 🪤 IT FAILS TOWARD "NOT NARROWED", which is the direction that hides the thing this view
    # exists to show -- and with three admins it printed "3 of 2 tenant(s)", an impossible number
    # nobody was going to see because nobody re-reads a summary line that looks plausible.
    # So: one cell per (tag, tenant), and a tenant REACHES if ANY of its assignments project.
    $byTag = @{}
    function Add-ReachCell($tag, $tenant, $state, $why, $bucket) {
        if (-not "$tag".Trim()) { return }
        $k = "$tag".Trim()
        if (-not $byTag.ContainsKey($k)) { $byTag[$k] = [ordered]@{} }
        $tid = "$($tenant.tenantId)"
        if (-not $byTag[$k].Contains($tid)) {
            $byTag[$k][$tid] = [ordered]@{
                tenantId = $tid; name = "$($tenant.name)"; ring = $tenant.ring
                reaches  = $false
                reasons  = New-Object System.Collections.Generic.List[object]
            }
        }
        $cell = $byTag[$k][$tid]
        if ($state -eq 'reach') { $cell.reaches = $true; return }
        $axis = Get-PimProjectionWithholdAxis -Bucket $bucket -Reason "$why"
        # Two admins denied for the same reason is ONE fact about the tenant, not two.
        $sig = "$axis|$why"
        if (-not @($cell.reasons.ToArray() | Where-Object { "$($_.sig)" -eq $sig }).Count) {
            [void]$cell.reasons.Add([ordered]@{ sig = $sig; axis = $axis; reason = "$why" })
        }
    }

    $allTenants = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Relationships)) {
        if (-not $r) { continue }
        $allTenants.Add([ordered]@{ tenantId = "$($r.tenantId)"; name = "$($r.name)" }) | Out-Null
        foreach ($p in @($r.projected))  { Add-ReachCell (Get-PimDownlinkValue -Object $p -Key 'GroupTag') $r 'reach'    '' 'projected' }
        foreach ($e in @($r.excluded))   { Add-ReachCell (Get-PimDownlinkValue -Object $e -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $e -Key 'reason') 'excluded' }
        foreach ($u in @($r.unresolved)) { Add-ReachCell (Get-PimDownlinkValue -Object $u -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $u -Key 'reason') 'unresolved' }
        # The two narrowings that happen UPSTREAM of the projection. Without these the tenant is
        # in neither list and the row silently shrinks its own denominator -- see the overview.
        foreach ($n in @(Get-PimDownlinkValue -Object $r -Key 'notTargeted')) {
            Add-ReachCell (Get-PimDownlinkValue -Object $n -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $n -Key 'reason') 'notTargeted'
        }
        foreach ($c in @(Get-PimDownlinkValue -Object $r -Key 'classHeld')) {
            Add-ReachCell (Get-PimDownlinkValue -Object $c -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $c -Key 'reason') 'classHeld'
        }
    }

    $total = @($Relationships).Count
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in ($byTag.Keys | Sort-Object)) {
        $cells = @(@($byTag[$k].Values) | Sort-Object @{ e = { "$($_.name)".ToLowerInvariant() } })
        $reach = New-Object System.Collections.Generic.List[object]
        $held  = New-Object System.Collections.Generic.List[object]
        foreach ($c in $cells) {
            $reasons = @($c.reasons.ToArray())
            if ($c.reaches) {
                # The role DOES land here. If another admin's copy of the same tag was held back
                # in this tenant, that is worth showing -- but it is not a withholding of the ROLE,
                # and counting it as one is what produced the impossible numbers above.
                $reach.Add([ordered]@{
                    tenantId = $c.tenantId; name = $c.name; ring = $c.ring
                    partial  = ($reasons.Count -gt 0)
                    partialReason = $(if ($reasons.Count) { "$($reasons[0].reason)" } else { '' })
                }) | Out-Null
            } else {
                $axes = @(@($reasons | ForEach-Object { "$($_.axis)" }) | Select-Object -Unique)
                $axis = 'other'
                if ($axes.Count -eq 1) { $axis = "$($axes[0])" } elseif ($axes.Count -gt 1) { $axis = 'mixed' }
                $held.Add([ordered]@{
                    tenantId = $c.tenantId; name = $c.name; ring = $c.ring
                    # 🔒 `axis` is what the WRITE half reads. `mixed` is not policy, so it refuses.
                    axis     = $axis
                    axes     = @($axes)
                    reason   = $(if ($reasons.Count) { "$($reasons[0].reason)" } else { '' })
                    reasons  = @($reasons | ForEach-Object { [ordered]@{ axis = "$($_.axis)"; reason = "$($_.reason)" } })
                }) | Out-Null
            }
        }
        $reachArr = @($reach.ToArray()); $heldArr = @($held.ToArray())
        # 🔒 THE ACCOUNTING LINE EXISTS BECAUSE THE BUG ABOVE WAS INVISIBLE. A tenant that appears
        # in NEITHER list does not make the view look wrong -- it makes the denominator quietly
        # smaller, which reads as a perfectly ordinary answer. Stating reaches + withheld against
        # the tenant count turns "absent" into something a test and an operator can both see.
        $missing = @(@($allTenants.ToArray()) | Where-Object { -not $byTag[$k].Contains("$($_.tenantId)") })
        $out.Add([ordered]@{
            groupTag      = $k
            reachCount    = $reachArr.Count
            tenantCount   = $total
            # The sentence the operator actually asked for, precomputed so the GUI cannot
            # render a different arithmetic than the API reported.
            summary       = ("{0} of {1} tenant(s)" -f $reachArr.Count, $total)
            # 🔒 A tag that reaches EVERY tenant is not narrowed. Flagged so "5 of 28" stands out
            # from "28 of 28" at a glance -- the whole point is spotting the narrow ones.
            narrowed      = ($reachArr.Count -lt $total)
            reaches       = $reachArr
            withheld      = $heldArr
            accountedFor  = ($reachArr.Count + $heldArr.Count)
            unaccounted   = $missing.Count
            unaccountedTenants = @($missing | ForEach-Object { "$($_.name)" })
        }) | Out-Null
    }
    return @($out.ToArray())
}

# --- MSP-4, the WRITE half: authoring narrowing along the TAG axis -----------

function Get-PimProjectionReachEdit {
    <#
      MSP-4 -- THE WRITE HALF, as a PURE plan. Given "'$GroupTag' should reach exactly these
      tenants", work out the per-relationship rule sets that would deliver it -- or REFUSE.

      🔑 THE REACH VIEW WAS BUILT FIRST AND KEPT READ-ONLY ON PURPOSE: you cannot safely author
      a narrowing you cannot yet audit. This is the other half, and it is deliberately the same
      shape -- the operator edits the TRANSPOSE (one role, N tenants) and the store still holds
      per-tenant rows, so this function is the translation and nothing else writes.

      🔴 THE FAILURE THIS EXISTS TO PREVENT IS "GRANTED" REPORTED FOR A GRANT THAT DID NOT
      HAPPEN. Four different narrowings can hold a role out of a tenant and only ONE of them --
      `policy` -- is writable from here. Ticking a tenant that is held back by its RING, by the
      artifact's own Target selector, or by a capability the customer blocked would write a rule,
      commit cleanly, change nothing, and show a green result. That is this codebase's most
      expensive recurring defect (phantom applied work, BUG-70b), pointed at someone else's
      tenant. So an undeliverable grant is REFUSED, by name, before anything is written.

      🔒 THE TWO DIRECTIONS ARE DELIBERATELY ASYMMETRIC, and the asymmetry always errs toward
      LESS privilege:
        * a GRANT is refused unless `policy` is demonstrably the only thing in the way;
        * a WITHHOLD is always written, even when the role is already held back by another axis,
          because that other axis can change (a ring is raised, a Target is rewritten) and the
          operator's intent must outlive it. It is reported as `alreadyWithheldBy` so the record
          does not pretend the deny is what is doing the work today.

      🪤 A WILDCARD DENY IS NOT MINE TO REMOVE. If `ROLE-*` is what excludes this tag, deleting
      it to grant one role silently widens the tenant's projection to every role that pattern was
      holding back. Refused, naming the rule, and sent to the per-tenant policy panel where the
      blast radius is visible.

      PURE: no SQL, no network. Takes the reach entry, the estate list and the current rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupTag,
        [AllowEmptyCollection()][string[]]$DesiredTenantIds = @(),
        $ReachEntry,
        [AllowEmptyCollection()][object[]]$Tenants = @(),
        $CurrentPolicies
    )
    $tag = "$GroupTag".Trim()
    $tagLc = $tag.ToLowerInvariant()

    $want = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($DesiredTenantIds)) { [void]$want.Add("$t".Trim().ToLowerInvariant()) }

    # tenantId -> the reach view's own verdict for this tag
    $state = @{}
    foreach ($r in @(Get-PimDownlinkValue -Object $ReachEntry -Key 'reaches')) {
        $k = "$(Get-PimDownlinkValue -Object $r -Key 'tenantId')".Trim().ToLowerInvariant()
        if ($k) { $state[$k] = [ordered]@{ reaches = $true; axis = ''; reason = '' } }
    }
    foreach ($w in @(Get-PimDownlinkValue -Object $ReachEntry -Key 'withheld')) {
        $k = "$(Get-PimDownlinkValue -Object $w -Key 'tenantId')".Trim().ToLowerInvariant()
        if ($k) { $state[$k] = [ordered]@{ reaches = $false
                                           axis    = "$(Get-PimDownlinkValue -Object $w -Key 'axis')"
                                           reason  = "$(Get-PimDownlinkValue -Object $w -Key 'reason')" } }
    }

    $refusals  = New-Object System.Collections.Generic.List[object]
    $edits     = New-Object System.Collections.Generic.List[object]
    $unchanged = New-Object System.Collections.Generic.List[object]

    foreach ($t in @($Tenants)) {
        $tid  = "$(Get-PimDownlinkValue -Object $t -Key 'tenantId')".Trim()
        if (-not $tid) { continue }
        $key  = $tid.ToLowerInvariant()
        $name = "$(Get-PimDownlinkValue -Object $t -Key 'name')"
        if (-not $name) { $name = $tid }
        $wantReach = $want.Contains($key)

        $rules = @()
        if ($null -ne $CurrentPolicies) {
            $got = Get-PimDownlinkValue -Object $CurrentPolicies -Key $key
            if ($null -eq $got) { $got = Get-PimDownlinkValue -Object $CurrentPolicies -Key $tid }
            if ($null -ne $got) { $rules = @($got) }
        }
        $denyHits = @(@($rules) | Where-Object {
            "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'deny' -and
            (Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')") })
        $allowRules = @(@($rules) | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'allow' })
        $allowHits  = @($allowRules | Where-Object { Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })

        $st = $null
        if ($state.ContainsKey($key)) { $st = $state[$key] }

        if ($wantReach) {
            if ($null -eq $st) {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = 'absent'
                    reason = "'$tag' is not part of $name's plan at all -- there is no assignment here to let through." }) | Out-Null
                continue
            }
            if ($st.reaches) {
                $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "already reaches $name" }) | Out-Null
                continue
            }
            if ("$($st.axis)" -ne 'policy') {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = "$($st.axis)"
                    reason = "$name is held back by $($st.axis), not by the relationship policy -- a rule written here would change nothing and report success. ($($st.reason))" }) | Out-Null
                continue
            }
            $broad = @($denyHits | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".Trim().ToLowerInvariant() -ne $tagLc })
            if ($broad.Count) {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = 'policy'
                    reason = "a WILDCARD deny ('$(Get-PimDownlinkValue -Object $broad[0] -Key 'GroupTag')') is what excludes '$tag' in $name; removing it here would widen that tenant's projection to every role it covers. Edit it on $name's own policy panel, where that blast radius is visible." }) | Out-Null
                continue
            }
            $newRules = New-Object System.Collections.Generic.List[object]
            foreach ($r in @($rules)) {
                $isHit = @($denyHits | Where-Object {
                    "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')" -eq "$(Get-PimDownlinkValue -Object $r -Key 'Mode')" -and
                    "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" -eq "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')" })
                if ($isHit.Count) { continue }
                $newRules.Add([ordered]@{ Mode = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
                                          GroupTag = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim() }) | Out-Null
            }
            # An allow-LIST is only a list while it has entries: with allow rules present, a tag
            # that matches none of them is excluded even with every deny gone.
            if ($allowRules.Count -and -not $allowHits.Count) {
                $newRules.Add([ordered]@{ Mode = 'allow'; GroupTag = $tag }) | Out-Null
            }
            $edits.Add([ordered]@{ tenantId = $tid; name = $name; action = 'grant'; rules = @($newRules.ToArray()) }) | Out-Null
            continue
        }

        # want = withhold
        if ($null -eq $st) {
            $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "'$tag' is not in $name's plan -- nothing to withhold." }) | Out-Null
            continue
        }
        if ($denyHits.Count) {
            $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "already denied by '$(Get-PimDownlinkValue -Object $denyHits[0] -Key 'GroupTag')'" }) | Out-Null
            continue
        }
        $newRules = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($rules)) {
            $newRules.Add([ordered]@{ Mode = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
                                      GroupTag = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim() }) | Out-Null
        }
        $newRules.Add([ordered]@{ Mode = 'deny'; GroupTag = $tag }) | Out-Null
        $already = ''
        if (-not $st.reaches) { $already = "$($st.axis)" }
        $edits.Add([ordered]@{ tenantId = $tid; name = $name; action = 'withhold'
                               alreadyWithheldBy = $already; rules = @($newRules.ToArray()) }) | Out-Null
    }

    return [ordered]@{
        ok        = (@($refusals.ToArray()).Count -eq 0)
        groupTag  = $tag
        refusals  = @($refusals.ToArray())
        edits     = @($edits.ToArray())
        unchanged = @($unchanged.ToArray())
    }
}

function Set-PimProjectionReach {
    <#
      MSP-4 -- apply a tag-axis reach edit, then MEASURE what it actually did.

      🔴 THE VERDICT IS RE-MEASURED, NOT ASSUMED. The plan above says what the rules should
      deliver; this re-composes the whole downlink overview AFTER the commit and reads the reach
      back out. "I wrote the rows I intended" and "the role now reaches the tenants you asked
      for" are different claims, and only the second is the one the operator made. If they
      disagree the result is NOT ok -- loudly, with the difference named -- even though the write
      succeeded. A write that reports success it cannot demonstrate is how this project has
      repeatedly shipped phantom work.

      Nothing is written when the plan carries a single refusal: a partial narrowing is not a
      smaller narrowing, and the operator asked for one estate-wide statement.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupTag,
        [AllowEmptyCollection()][string[]]$TenantIds = @(),
        [string]$ConnectionString,
        [string]$BaselinePath
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $tag = "$GroupTag".Trim()

    $ovArgs = @{ ConnectionString = $ConnectionString }
    if ($BaselinePath) { $ovArgs['BaselinePath'] = $BaselinePath }

    $before      = Get-PimManagerDownlinkOverview @ovArgs
    $reachBefore = @(Get-PimProjectionReach -Relationships @($before.relationships))
    $entry       = @($reachBefore | Where-Object { "$($_.groupTag)".Trim().ToLowerInvariant() -eq $tag.ToLowerInvariant() })
    if (-not $entry.Count) {
        throw "'$tag' is not a role in the current plan -- nothing was written. (Roles come from the SIGNED baseline; a tag the bundle does not define cannot be narrowed.)"
    }

    $tenants  = @(@($before.relationships) | ForEach-Object { [ordered]@{ tenantId = "$($_.tenantId)"; name = "$($_.name)" } })
    $policies = [ordered]@{}
    foreach ($r in @($before.relationships)) { $policies["$($r.tenantId)".Trim().ToLowerInvariant()] = @($r.policy) }

    $plan = Get-PimProjectionReachEdit -GroupTag $tag -DesiredTenantIds @($TenantIds) `
                -ReachEntry $entry[0] -Tenants $tenants -CurrentPolicies $policies
    if (-not $plan.ok) {
        return [ordered]@{
            ok = $false; wrote = $false; groupTag = $tag
            refusals = @($plan.refusals); edits = @($plan.edits); unchanged = @($plan.unchanged)
            before = "$($entry[0].summary)"; after = "$($entry[0].summary)"
            detail = "REFUSED -- nothing was written. $(@($plan.refusals).Count) tenant(s) cannot be set from this view."
        }
    }

    $wrote = 0
    if (@($plan.edits).Count) {
        $wrote = Set-PimManagerDownlinkPolicyMany -Edits @(@($plan.edits) | ForEach-Object { [ordered]@{ TenantId = "$($_.tenantId)"; Rules = @($_.rules) } }) `
                    -ConnectionString $ConnectionString -Note "MSP-4 reach edit for '$tag'"
    }

    $after      = Get-PimManagerDownlinkOverview @ovArgs
    $reachAfter = @(Get-PimProjectionReach -Relationships @($after.relationships))
    $entryAfter = @($reachAfter | Where-Object { "$($_.groupTag)".Trim().ToLowerInvariant() -eq $tag.ToLowerInvariant() })

    $got = New-Object System.Collections.Generic.HashSet[string]
    if ($entryAfter.Count) {
        foreach ($r in @($entryAfter[0].reaches)) { [void]$got.Add("$($r.tenantId)".Trim().ToLowerInvariant()) }
    }
    $askedFor = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($TenantIds)) { [void]$askedFor.Add("$t".Trim().ToLowerInvariant()) }

    $missing = @(@($askedFor) | Where-Object { -not $got.Contains($_) })
    $extra   = @(@($got)      | Where-Object { -not $askedFor.Contains($_) })
    $delivered = ((@($missing).Count -eq 0) -and (@($extra).Count -eq 0))

    $nameOf = @{}
    foreach ($t in $tenants) { $nameOf["$($t.tenantId)".Trim().ToLowerInvariant()] = "$($t.name)" }
    $named = { param($ids) @(@($ids) | ForEach-Object { if ($nameOf.ContainsKey("$_")) { $nameOf["$_"] } else { "$_" } }) }

    $detail = "'$tag' now reaches $(if ($entryAfter.Count) { "$($entryAfter[0].summary)" } else { "0 of $(@($tenants).Count) tenant(s)" }); $wrote relationship(s) rewritten."
    if (-not $delivered) {
        $detail = "WROTE $wrote relationship(s), BUT THE RESULT IS NOT WHAT WAS ASKED FOR. " +
                  "$(if (@($missing).Count) { "still not reaching: $((& $named $missing) -join ', '). " } else { '' })" +
                  "$(if (@($extra).Count) { "unexpectedly reaching: $((& $named $extra) -join ', '). " } else { '' })" +
                  "The rules were committed; the reach was re-measured and disagrees."
    }
    return [ordered]@{
        ok        = $delivered
        wrote     = ($wrote -gt 0)
        groupTag  = $tag
        refusals  = @()
        edits     = @($plan.edits)
        unchanged = @($plan.unchanged)
        before    = "$($entry[0].summary)"
        after     = $(if ($entryAfter.Count) { "$($entryAfter[0].summary)" } else { '' })
        missing   = @(& $named $missing)
        extra     = @(& $named $extra)
        detail    = $detail
    }
}

# --- the run -----------------------------------------------------------------

function Invoke-PimManagerDownlinkRun {
    <#
      PREVIEW ONLY, and deliberately so.

      🔴 THIS USED TO WRITE INTO THE MANAGED TENANT'S STORE, AND THAT WAS WRONG TWICE OVER.
      It broke the standing Do-Not in docs/REQUIREMENTS.md §22 -- "MSP never writes to a
      customer tenant" -- and the pull-not-push tenet PIM-Downlink.ps1 asserts throughout.
      It was also simply broken: a Manager in the master holds the MASTER's ambient
      identity, and Get-PimSqlConnectionString mints its Azure SQL token from that, so the
      connection authenticated as the wrong tenant entirely.

      📌 THE AGREED MODEL (framework MSP-3, operator 2026-08-13) removes the need rather
      than licensing it: the managed tenant PULLS, decides locally with its own identity,
      and its own administrator ACCEPTS before anything applies. So the master side of this
      feature PUBLISHES a version; it never reaches in.

      What remains is the PREVIEW an MSP operator legitimately needs -- "what would this
      customer receive if they pulled right now" -- computed from the signed bundle and the
      master's own registry, touching nothing.
      ◻ The publish/release action and the customer-side accept surface are MSP-3 work and
      are not built yet. This function must NOT grow a write path back.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ConnectionString,
        [string]$BaselinePath,
        [switch]$WhatIfMode = $true
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $t = @(Get-PimManagerDownlinkTenants -ConnectionString $ConnectionString | Where-Object { "$($_.TenantId)" -eq $TenantId }) | Select-Object -First 1
    if (-not $t) { return @{ ok = $false; detail = "tenant $TenantId is not a registered managed relationship." } }

    if (-not $WhatIfMode) {
        # Refuse LOUDLY rather than silently downgrading to a preview: an operator who asked
        # to apply must never be shown a green "done" for something that did nothing.
        return @{ ok = $false; whatIf = $true; detail = @(
            'REFUSED: the master does not write into a managed tenant.',
            '',
            'Under the agreed model (framework MSP-3) the managed tenant PULLS the signed baseline,',
            'decides locally with its own identity, and its own administrator ACCEPTS it before',
            'anything applies. Nothing crosses a tenant boundary in the other direction.',
            '',
            'Use Dry run to preview what this customer would receive. To make it real, publish the',
            'baseline version for their ring; their engine collects it on its next run.'
        ) -join "`n" }
    }

    $bl = Get-PimManagerBaselineDoc -Path $BaselinePath
    if (-not $bl.doc) { return @{ ok = $false; detail = "$($bl.error)" } }

    # No slave-side tag list: reading one would mean reaching into the customer's store.
    # Omitting it makes the plan treat every tag the bundle defines as creatable, which is
    # the honest preview -- the tenant resolves the rest itself when it pulls.
    # 🔴 NOT $env:TEMP -- unset in the Linux container (see the sibling call above).
    $planArgs = @{ Scenario = 'S6'; Doc = $bl.doc; TenantId = $TenantId; SlaveRing = [int]("0" + "$($t.Ring)"); LocalRoot = [System.IO.Path]::GetTempPath() }
    $plan = Get-PimDownlinkPlan @planArgs
    if (-not $plan.ok) { return @{ ok = $false; detail = "refused: $($plan.reason)" } }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("PREVIEW for $($t.DisplayName) -- nothing was written.") | Out-Null
    $lines.Add("$($plan.reason)") | Out-Null
    $lines.Add("admins offered : $(@($plan.admins).Count)") | Out-Null
    $lines.Add("roles offered  : $(@($plan.assignments).Count)") | Out-Null
    if ($plan.definitions) { $lines.Add("groups offered : $(@($plan.definitions.create).Count)") | Out-Null }
    foreach ($e in @($plan.projection.excluded))   { $lines.Add("held back  $($e.UserName) -> $($e.GroupTag): $($e.reason)") | Out-Null }
    foreach ($u in @($plan.projection.unresolved)) { $lines.Add("UNRESOLVED $($u.UserName) -> $($u.GroupTag): $($u.reason)") | Out-Null }
    return @{ ok = $true; whatIf = $true; detail = ($lines.ToArray() -join "`n") }
}
