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

function Set-PimManagerDownlinkPolicy {
    <#
      Replace the rule set for ONE relationship, IN ONE TRANSACTION.
      Full-set replace is correct here: the rows are scoped by TenantId so no other
      relationship is touched, and the GUI always submits the complete list it rendered.

      🔒 THE TRANSACTION IS THE WHOLE POINT, NOT TIDINESS. This is DELETE-then-INSERT, and
      "no rows for a tenant" is not a neutral state -- it means ALLOW ALL. So a failure
      between the delete and the last insert would leave the relationship projecting
      EVERYTHING the master publishes: an error that silently WIDENS privilege. That is
      ESTATE-14's failure class (an unchecked failure presented as a state of the world),
      and it is the reason this cannot be two separate statements.

      Validation happens BEFORE the write for the same reason: a rule rejected halfway
      through would already have had its predecessors committed.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$TenantId,
        [object[]]$Rules = @(),
        [string]$ConnectionString
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }

    # validate first -- nothing is written unless every rule is acceptable
    $clean = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rules)) {
        $m = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
        $g = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim()
        if ($m -notin @('allow','deny')) { throw "invalid Mode '$m' -- must be allow or deny (nothing was written)." }
        if (-not $g) { throw "a rule is missing its GroupTag (nothing was written)." }
        $clean.Add([ordered]@{ Mode = $m; GroupTag = $g }) | Out-Null
    }

    $cn = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $cn.Open()
        $tx = $cn.BeginTransaction()
        $del = $cn.CreateCommand(); $del.Transaction = $tx
        $del.CommandText = 'DELETE FROM pim.TenantRoleProjection WHERE TenantId = @t'
        [void]$del.Parameters.AddWithValue('@t', $TenantId)
        [void]$del.ExecuteNonQuery()
        foreach ($c in $clean.ToArray()) {
            $ins = $cn.CreateCommand(); $ins.Transaction = $tx
            $ins.CommandText = 'INSERT INTO pim.TenantRoleProjection (TenantId, Mode, GroupTag, Notes) VALUES (@t, @m, @g, @n)'
            [void]$ins.Parameters.AddWithValue('@t', $TenantId)
            [void]$ins.Parameters.AddWithValue('@m', $c.Mode)
            [void]$ins.Parameters.AddWithValue('@g', $c.GroupTag)
            [void]$ins.Parameters.AddWithValue('@n', 'set from the Manager')
            [void]$ins.ExecuteNonQuery()
        }
        $tx.Commit(); $tx = $null
    } catch {
        if ($tx) { try { $tx.Rollback() } catch {} }
        throw "projection policy NOT changed (rolled back): $($_.Exception.Message)"
    } finally {
        try { $cn.Close() } catch {}
    }
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
                $planArgs = @{
                    Scenario = 'S6'; Doc = $bl.doc; TenantId = $tid
                    SlaveRing = $entry.ring; LocalRoot = $env:TEMP
                }
                $plan = Get-PimDownlinkPlan @planArgs
                if (-not $plan.ok) { $entry.error = "$($plan.reason)" }
                else {
                    $entry.adminCount = @($plan.admins).Count
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
    $planArgs = @{ Scenario = 'S6'; Doc = $bl.doc; TenantId = $TenantId; SlaveRing = [int]("0" + "$($t.Ring)"); LocalRoot = $env:TEMP }
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
