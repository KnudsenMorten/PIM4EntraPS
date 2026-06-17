#Requires -Version 5.1
<#
.SYNOPSIS
    Delegation Map risk overlay + search-result builder -- PURE, offline,
    unit-testable. (REQUIREMENTS §28 [M8].)

.DESCRIPTION
    Two pure functions over the SAME node/edge model the Delegation Map renders
    (Build-PimGraphData / Get-PimAccessGraphModel). No SQL, no Graph, no HTTP --
    everything is computed from the in-memory model so it can be seeded + tested
    offline and reused by the server endpoint.

      Get-PimMapSearchResults  -- typed, ordered result LIST for the Map's search
                                  box (people / role groups / permission groups /
                                  targets / scopes). Each hit carries the node id
                                  the GUI uses to JUMP (center + select).

      Get-PimMapRiskOverlay    -- per-node risk classification computed from the
                                  REAL reach graph:
                                    * ORPHAN   -- a delegation/permission group
                                                  with no admin path INTO it (no
                                                  principal can ever reach it) OR
                                                  a target no principal reaches.
                                    * STALE    -- a node past its review horizon
                                                  (only when the model carries a
                                                  lastReviewedUtc / reviewDays
                                                  signal -- never invented).
                                    * OVERPRIV -- a principal/group that reaches a
                                                  T0/T1-tier node, OR reaches an
                                                  EMPIRICALLY high number of targets
                                                  (mean + 1 stddev over the actual
                                                  reach-count distribution -- NO
                                                  hardcoded MaxN cap).

    Reach semantics are IDENTICAL to Get-PimAccessGraphModel / the Map's
    buildMapModel: column-oriented (admin=0, role-group=1, permission-group=2,
    target=3), group nesting oriented low-col -> high-col, same-column nest
    dropped, cosmetic / au-to-au-role edges excluded.

    PowerShell 5.1 safe: no ?./??, no null-conditional, every node field read
    through a guarded accessor that never throws on a missing property.
#>

# --- node-field accessor (ordered hashtable OR PSCustomObject) ----------------
# Local copy so this lib is self-contained when dot-sourced by the offline test
# (Open-PimManager.ps1 has its own Get-PimNodeField; defining ours under a
# distinct name avoids clobbering / depending on load order).
function Get-PimMapNodeField {
    param($Node, [string]$Name)
    if ($null -eq $Node) { return '' }
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) { return "$($Node[$Name])" }
        return ''
    }
    if ($Node.PSObject.Properties[$Name]) { return "$($Node.PSObject.Properties[$Name].Value)" }
    return ''
}

function Get-PimMapNodeLabel {
    param($Node, [string]$Id)
    $lbl = Get-PimMapNodeField -Node $Node -Name 'label'
    if ("$lbl".Trim()) { return "$lbl" }
    return "$Id"
}

# --- column of a node (the reach LAYER) ---------------------------------------
function Get-PimMapColumn {
    param([string]$Kind)
    switch ($Kind) {
        'admin'            { return 0 }
        'role-group'       { return 1 }
        'permission-group' { return 2 }
        'entra-role'       { return 3 }
        'au-role'          { return 3 }
        'az-resource'      { return 3 }
        default            { return -1 }
    }
}

# --- normalise the model into fast lookups (idempotent over Build-PimGraphData
#     output: { nodes=[]; edges=[] }) ------------------------------------------
function ConvertTo-PimMapReach {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)
    $nodes = @($Data.nodes)
    $edges = @($Data.edges)
    $byId = @{}
    foreach ($n in $nodes) {
        $id = Get-PimMapNodeField -Node $n -Name 'id'
        if ("$id".Trim()) { $byId["$id"] = $n }
    }
    $kindOf = {
        param($Id)
        if ($byId.ContainsKey("$Id")) { return (Get-PimMapNodeField -Node $byId["$Id"] -Name 'kind') }
        return ''
    }
    $fwd = @{}    # source -> [targetId,...]
    $back = @{}   # target -> [sourceId,...]
    foreach ($e in $edges) {
        $cosmetic = Get-PimMapNodeField -Node $e -Name 'cosmetic'
        $kind     = Get-PimMapNodeField -Node $e -Name 'kind'
        if ($cosmetic -eq 'True' -or $cosmetic -eq $true -or $kind -eq 'au-to-au-role') { continue }
        $s = "$(Get-PimMapNodeField -Node $e -Name 'source')"
        $t = "$(Get-PimMapNodeField -Node $e -Name 'target')"
        if (-not $s -or -not $t) { continue }
        if ($kind -eq 'group-to-group') {
            $cs = Get-PimMapColumn (& $kindOf $s)
            $ct = Get-PimMapColumn (& $kindOf $t)
            if ($cs -lt 0 -or $ct -lt 0) { continue }
            if ($cs -eq $ct) { continue }                 # same-column nest = not a reach hop
            if ($cs -gt $ct) { $tmp = $s; $s = $t; $t = $tmp }  # orient low-col -> high-col
        }
        if (-not $fwd.ContainsKey($s)) { $fwd[$s] = New-Object System.Collections.ArrayList }
        [void]$fwd[$s].Add($t)
        if (-not $back.ContainsKey($t)) { $back[$t] = New-Object System.Collections.ArrayList }
        [void]$back[$t].Add($s)
    }
    return @{ nodes = $nodes; byId = $byId; fwd = $fwd; back = $back }
}

# --- BFS over a direction map -------------------------------------------------
function Get-PimMapDownstream {
    param($Model, [string]$StartId)
    $seen = @{}; $seen["$StartId"] = $true
    $q = New-Object System.Collections.Queue; $q.Enqueue("$StartId")
    while ($q.Count -gt 0) {
        $cur = $q.Dequeue()
        if ($Model.fwd.ContainsKey($cur)) {
            foreach ($nx in $Model.fwd[$cur]) {
                if (-not $seen.ContainsKey($nx)) { $seen[$nx] = $true; $q.Enqueue($nx) }
            }
        }
    }
    [void]$seen.Remove("$StartId")
    return @($seen.Keys)
}

function Get-PimMapUpstream {
    param($Model, [string]$StartId)
    $seen = @{}; $seen["$StartId"] = $true
    $q = New-Object System.Collections.Queue; $q.Enqueue("$StartId")
    while ($q.Count -gt 0) {
        $cur = $q.Dequeue()
        if ($Model.back.ContainsKey($cur)) {
            foreach ($nx in $Model.back[$cur]) {
                if (-not $seen.ContainsKey($nx)) { $seen[$nx] = $true; $q.Enqueue($nx) }
            }
        }
    }
    [void]$seen.Remove("$StartId")
    return @($seen.Keys)
}

# =============================================================================
# SEARCH -> ordered result list with JUMP coordinates
# =============================================================================
function Get-PimMapSearchResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query,
        [int]$Limit = 50
    )
    $q = "$Query".Trim().ToLowerInvariant()
    $hits = New-Object System.Collections.ArrayList
    if (-not $q) { return [ordered]@{ query = ''; count = 0; truncated = $false; hits = @() } }

    $typeFor = {
        param($Kind)
        switch ($Kind) {
            'admin'            { 'person' }
            'role-group'       { 'group' }
            'permission-group' { 'group' }
            'au'               { 'scope' }
            'entra-role'       { 'role' }
            'au-role'          { 'role' }
            'az-resource'      { 'scope' }
            default            { 'other' }
        }
    }
    # Column = the board column the GUI scrolls/centres to. Targets/scopes live in
    # col 3; an AU node (kind 'au') is a scope shown on col 3 too.
    foreach ($n in @($Data.nodes)) {
        $nk  = Get-PimMapNodeField -Node $n -Name 'kind'
        $nid = Get-PimMapNodeField -Node $n -Name 'id'
        if (-not "$nid".Trim()) { continue }
        $matched = ''
        foreach ($k in 'label','id','groupTag','roleName','scopePath','scopeShort','auTag','description','tier','level','purpose') {
            $v = Get-PimMapNodeField -Node $n -Name $k
            if ("$v".Trim() -and "$v".ToLowerInvariant().Contains($q)) { $matched = "$v"; break }
        }
        if (-not $matched) { continue }
        $type = & $typeFor $nk
        $col  = Get-PimMapColumn $nk
        if ($col -lt 0 -and $nk -eq 'au') { $col = 3 }
        [void]$hits.Add([ordered]@{
            id      = "$nid"
            type    = $type
            kind    = $nk
            label   = (Get-PimMapNodeLabel -Node $n -Id $nid)
            matched = $matched
            column  = $col
        })
    }
    # Stable order: type rank (person, group, role, scope, other) then label.
    $typeRank = @{ person = 0; group = 1; role = 2; scope = 3; other = 4 }
    $sorted = @($hits | Sort-Object `
        @{ Expression = { [int]$typeRank["$($_.type)"] } }, `
        @{ Expression = { "$($_.label)".ToLowerInvariant() } })
    $total = @($sorted).Count
    $page  = if ($total -gt $Limit) { @($sorted | Select-Object -First $Limit) } else { $sorted }
    return [ordered]@{
        query     = "$Query".Trim()
        count     = $total
        truncated = ($total -gt $Limit)
        hits      = @($page)
    }
}

# =============================================================================
# RISK OVERLAY -> per-node orphan / stale / over-privileged classification
# =============================================================================
function Get-PimMapRiskOverlay {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)

    $model = ConvertTo-PimMapReach -Data $Data
    $nodes = @($model.nodes)

    # --- forward reach (targets reached) per principal/group ------------------
    # A "principal" for over-priv purposes is an admin (col0) or a group (col1/2):
    # any node that can reach targets. We measure reach = distinct col-3 targets
    # downstream. T0/T1 reach is a hard over-priv signal regardless of count.
    $tierOf = {
        param($Id)
        if ($model.byId.ContainsKey("$Id")) {
            return ("$(Get-PimMapNodeField -Node $model.byId["$Id"] -Name 'tier')").Trim().ToUpperInvariant()
        }
        return ''
    }
    $isTarget = {
        param($Id)
        $k = ''
        if ($model.byId.ContainsKey("$Id")) { $k = Get-PimMapNodeField -Node $model.byId["$Id"] -Name 'kind' }
        return (@('entra-role','au-role','az-resource') -contains $k)
    }

    $reachInfo = @{}     # nodeId -> @{ targetCount; hitsT0T1 }
    $reachCounts = New-Object System.Collections.ArrayList
    foreach ($n in $nodes) {
        $id   = Get-PimMapNodeField -Node $n -Name 'id'
        $kind = Get-PimMapNodeField -Node $n -Name 'kind'
        $col  = Get-PimMapColumn $kind
        if ($col -lt 0 -or $col -eq 3) { continue }   # only principals/groups reach
        $down = Get-PimMapDownstream -Model $model -StartId "$id"
        $tCount = 0; $hiTier = $false
        foreach ($d in $down) {
            if (& $isTarget $d) {
                $tCount++
                $dt = & $tierOf $d
                if ($dt -eq 'T0' -or $dt -eq 'T1') { $hiTier = $true }
            } else {
                # a reached group's OWN tier can also be high (e.g. a T0 role group)
                $dt = & $tierOf $d
                if ($dt -eq 'T0' -or $dt -eq 'T1') { $hiTier = $true }
            }
        }
        $reachInfo["$id"] = @{ targetCount = $tCount; hitsT0T1 = $hiTier; col = $col }
        if ($tCount -gt 0) { [void]$reachCounts.Add($tCount) }
    }

    # --- EMPIRICAL high-reach threshold: mean + 1 sample-stddev over the actual
    #     non-zero reach-count distribution. NO arbitrary MaxN. With <2 data
    #     points (no spread to learn from) the count signal is disabled and only
    #     the T0/T1 reach signal flags over-priv.
    $counts = @($reachCounts | ForEach-Object { [double]$_ })
    $threshold = [double]::PositiveInfinity
    if ($counts.Count -ge 2) {
        $mean = ($counts | Measure-Object -Average).Average
        $var = 0.0
        foreach ($c in $counts) { $var += [math]::Pow($c - $mean, 2) }
        $sd = [math]::Sqrt($var / ($counts.Count - 1))
        $threshold = $mean + $sd
    }

    # --- per-node classification ---------------------------------------------
    $byNode = @{}     # nodeId -> [flag,...]
    $orphans = New-Object System.Collections.ArrayList
    $stale = New-Object System.Collections.ArrayList
    $overPriv = New-Object System.Collections.ArrayList

    $now = (Get-Date).ToUniversalTime()

    foreach ($n in $nodes) {
        $id   = Get-PimMapNodeField -Node $n -Name 'id'
        $kind = Get-PimMapNodeField -Node $n -Name 'kind'
        $col  = Get-PimMapColumn $kind
        if ($col -lt 0) { continue }
        $flags = New-Object System.Collections.ArrayList
        $reasons = @{}

        # ORPHAN ---------------------------------------------------------------
        # A delegation/permission group with NO admin path into it (no principal
        # upstream can ever reach it) is dead delegation. A target with NO
        # principal reaching it is unreachable / orphaned grant. Admins (col0)
        # are never "orphans" -- a person with no grants is a separate "reaches
        # nothing" gap, not an orphan group.
        if ($col -eq 1 -or $col -eq 2) {
            $up = Get-PimMapUpstream -Model $model -StartId "$id"
            $hasAdmin = $false
            foreach ($u in $up) {
                if ($model.byId.ContainsKey("$u") -and (Get-PimMapNodeField -Node $model.byId["$u"] -Name 'kind') -eq 'admin') { $hasAdmin = $true; break }
            }
            if (-not $hasAdmin) { [void]$flags.Add('orphan'); $reasons['orphan'] = 'No admin path reaches this group (dead delegation).' }
        } elseif ($col -eq 3) {
            $up = Get-PimMapUpstream -Model $model -StartId "$id"
            if ($up.Count -eq 0) { [void]$flags.Add('orphan'); $reasons['orphan'] = 'No principal reaches this target (unreachable grant).' }
        }

        # STALE ----------------------------------------------------------------
        # Only when the model carries a real review signal. lastReviewedUtc +
        # reviewDays (or a global review horizon) -> past horizon = stale. Never
        # invented when the data is absent.
        $lastReviewed = Get-PimMapNodeField -Node $n -Name 'lastReviewedUtc'
        $reviewDays   = Get-PimMapNodeField -Node $n -Name 'reviewDays'
        if ("$lastReviewed".Trim() -and "$reviewDays".Trim()) {
            [datetime]$dt = [datetime]::MinValue
            $ok = [datetime]::TryParse("$lastReviewed", [ref]$dt)
            [int]$days = 0; $okN = [int]::TryParse("$reviewDays", [ref]$days)
            if ($ok -and $okN -and $days -gt 0) {
                $ageDays = ($now - $dt.ToUniversalTime()).TotalDays
                if ($ageDays -gt $days) {
                    [void]$flags.Add('stale')
                    $reasons['stale'] = ("Last reviewed {0:N0} day(s) ago; review horizon is {1} day(s)." -f $ageDays, $days)
                }
            }
        }

        # OVER-PRIVILEGED ------------------------------------------------------
        if ($reachInfo.ContainsKey("$id")) {
            $ri = $reachInfo["$id"]
            $why = New-Object System.Collections.ArrayList
            if ($ri.hitsT0T1) { [void]$why.Add('reaches a Tier-0/Tier-1 target') }
            if ($ri.targetCount -gt $threshold) {
                [void]$why.Add(("reaches {0} targets (above the estate norm of {1:N1})" -f $ri.targetCount, $threshold))
            }
            if ($why.Count -gt 0) {
                [void]$flags.Add('overpriv')
                $reasons['overpriv'] = (($why.ToArray()) -join '; ') + '.'
            }
        }

        if ($flags.Count -gt 0) {
            $entry = [ordered]@{
                id     = "$id"
                kind   = $kind
                label  = (Get-PimMapNodeLabel -Node $n -Id $id)
                flags  = @($flags.ToArray())
                reasons = $reasons
            }
            $byNode["$id"] = $entry
            if ($flags -contains 'orphan')   { [void]$orphans.Add("$id") }
            if ($flags -contains 'stale')    { [void]$stale.Add("$id") }
            if ($flags -contains 'overpriv') { [void]$overPriv.Add("$id") }
        }
    }

    return [ordered]@{
        threshold = $threshold
        summary   = [ordered]@{
            orphan   = @($orphans).Count
            stale    = @($stale).Count
            overpriv = @($overPriv).Count
            flagged  = @($byNode.Keys).Count
        }
        nodes     = $byNode
        orphanIds   = @($orphans.ToArray())
        staleIds    = @($stale.ToArray())
        overprivIds = @($overPriv.ToArray())
    }
}

# =============================================================================
# STAGE-A-REMOVAL FROM THE MAP  (REQUIREMENTS §28 [M8] residual)
# =============================================================================
# The Delegation Map can already STAGE ADDS (admin->group, role-group nest); the
# residual is staging a REMOVAL (revoke a grant) directly from a flagged node or
# edge. This is the PURE core that turns a map selection into the row-level
# revocation plan -- WHICH assignment rows must be removed, from WHICH base, and
# the resulting "after" row set for that base. It does NOT write anything: the
# plan flows into the SAME Review & Save staged-change / keyed-diff / backup-undo
# / sensitive-maker-checker commit path the rest of the Manager uses (a removal
# is a 'delete-rows' replace-mode authoring action -- never a one-click bypass).
#
# Two selection modes, resolved against the SAME node/edge model the Map renders
# (Build-PimGraphData output: { nodes; edges }):
#   * EDGE  -- one concrete grant. The edge carries 'source_csv' (the owning base)
#              and 'match' (the natural-key fields of its source row). Remove every
#              row in that base whose key fields equal the edge's match. (A single
#              grant edge usually maps to exactly one row.)
#   * NODE  -- a flagged node (orphan target / over-privileged group / etc). Remove
#              every assignment row that REFERENCES that node id on either end:
#              admin rows into a group, nesting rows touching a group, and the
#              role/AU/Azure grant rows attaching a target to its group. Each
#              affected base gets its own plan entry.
#
# Reuses the edge 'match'/'source_csv' the graph builder already emits, and the
# natural-key shapes Get-PimAuthoringRowKey/Get-PimStoreRowKey use, so the staged
# removal keys IDENTICALLY to the keyed diff. PS 5.1-safe.

# Map an edge kind / target id to the assignment base it lives in. Cosmetic and
# non-assignment edges return '' (nothing to remove). Pure lookup.
function Get-PimMapEdgeBase {
    param([string]$Kind)
    switch ("$Kind") {
        'admin-to-group'        { return 'PIM-Assignments-Admins' }
        'group-to-group'        { return 'PIM-Assignments-Groups' }
        'group-to-entra-role'   { return 'PIM-Assignments-Roles-Groups' }
        'group-to-au-role'      { return 'PIM-Assignments-Roles-AUs' }
        'group-to-az-resource'  { return 'PIM-Assignments-Azure-Resources' }
        default                 { return '' }   # au-to-au-role (cosmetic) + unknown
    }
}

# The natural-key field list per assignment base. These are EXACTLY the fields the
# graph builder puts in each edge's 'match' dict and the fields Get-PimStoreRowKey
# keys on, so an edge match compares against a store row on the same identity.
function Get-PimMapBaseKeyFields {
    # Plural by intent (returns the LIST of key fields), matching this lib's
    # existing Get-PimMapSearchResults naming.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param([string]$Base)
    switch ("$Base") {
        'PIM-Assignments-Admins'          { return @('Username','GroupTag') }
        'PIM-Assignments-Groups'          { return @('TargetGroupTag','SourceGroupTag') }
        'PIM-Assignments-Roles-Groups'    { return @('GroupTag','RoleDefinitionName') }
        'PIM-Assignments-Roles-AUs'       { return @('GroupTag','AdministrativeUnitTag','RoleDefinitionName') }
        'PIM-Assignments-Azure-Resources' { return @('GroupTag','AzScope','AzScopePermission') }
        default                           { return @() }
    }
}

# TRUE when $Row matches every key field carried in $Match (case-insensitive,
# trimmed). Only the key fields are compared, so AssignmentType / day-count / other
# columns differing does NOT prevent a match -- a revocation drops the grant row
# regardless of its expiry settings. Pure.
function Test-PimMapRowMatchesEdge {
    param([Parameter(Mandatory)][string]$Base, [AllowNull()][object]$Row, [AllowNull()][object]$Match)
    if ($null -eq $Row -or $null -eq $Match) { return $false }
    $fields = Get-PimMapBaseKeyFields -Base $Base
    if (@($fields).Count -eq 0) { return $false }
    foreach ($f in $fields) {
        $rv = "$(Get-PimMapNodeField -Node $Row -Name $f)".Trim()
        $mv = "$(Get-PimMapNodeField -Node $Match -Name $f)".Trim()
        # A blank match value would match everything -- refuse it (over-broad).
        if ($mv -eq '') { return $false }
        if ($rv.ToLowerInvariant() -ne $mv.ToLowerInvariant()) { return $false }
    }
    return $true
}

# Does an edge REFERENCE node id $NodeId on EITHER end (after the same column
# orientation the reach model uses is irrelevant here -- we use the RAW edge ends
# the graph builder emitted, which point at the real source/target ids)? Pure.
function Test-PimMapEdgeTouchesNode {
    param([AllowNull()][object]$Edge, [string]$NodeId)
    if ($null -eq $Edge -or -not "$NodeId".Trim()) { return $false }
    $s = "$(Get-PimMapNodeField -Node $Edge -Name 'source')"
    $t = "$(Get-PimMapNodeField -Node $Edge -Name 'target')"
    return ($s -eq "$NodeId" -or $t -eq "$NodeId")
}

function Resolve-PimMapRemovalPlan {
    <#
      PURE core for "stage a removal from the Delegation Map" ([M8] residual).

      Given the live graph model ($Data: { nodes; edges } from Build-PimGraphData),
      the CURRENT store rows per assignment base ($CurrentRows: a hashtable
      base -> @(rows)), and ONE selection (an -EdgeMatch+-EdgeKind+-EdgeBase for a
      single grant, OR a -NodeId for a flagged node), return the revocation plan:

        @{
          ok            # $true when at least one removable row was resolved
          mode          # 'edge' | 'node'
          selection     # echo of what was selected (id / edge key)
          destructive   # ALWAYS $true for a removal (guard: a removal IS destructive)
          removedCount  # total rows that will be removed across all bases
          plans = @(    # one entry per affected base
            @{ base; afterRows; removedRows; removedCount; mode='replace' }
          )
          reasons       # human strings (why nothing matched, etc.)
        }

      The per-base 'afterRows' is the current set MINUS the matched rows -- i.e. a
      WHOLE-FILE REPLACE set. The caller stages that as a 'delete-rows' replace
      authoring action, so it routes through Get-PimAuthoringPreview (which reports
      the dropped rows as keyed REMOVES + a destructive flag), the sensitivity gate
      (the removed PRIVILEGED rows trip maker/checker), and Review & Save commit +
      backup/undo. NOTHING here writes; this only computes.

      DESTRUCTIVE GUARD: a removal that resolves to ZERO rows returns ok=$false with
      a reason (never an empty/over-broad plan). A node selection that would remove
      EVERY row of a base is reported with its exact count so the operator sees the
      blast radius before confirming -- it is never silently widened.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Edge')]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][hashtable]$CurrentRows,

        # --- EDGE selection (a single concrete grant) ---
        [Parameter(ParameterSetName = 'Edge')][AllowNull()][object]$EdgeMatch,
        [Parameter(ParameterSetName = 'Edge')][string]$EdgeKind = '',
        [Parameter(ParameterSetName = 'Edge')][string]$EdgeBase = '',

        # --- NODE selection (a flagged node -> revoke everything touching it) ---
        [Parameter(ParameterSetName = 'Node', Mandatory)][string]$NodeId
    )

    $reasons = New-Object System.Collections.ArrayList
    $plansByBase = [ordered]@{}     # base -> @{ removedRows[]; }
    $totalRemoved = 0

    $addRemoval = {
        param([string]$Base, [object]$Row)
        if (-not "$Base".Trim() -or $null -eq $Row) { return }
        if (-not $plansByBase.Contains($Base)) { $plansByBase[$Base] = New-Object System.Collections.ArrayList }
        [void]$plansByBase[$Base].Add($Row)
    }

    if ($PSCmdlet.ParameterSetName -eq 'Edge') {
        $base = "$EdgeBase".Trim()
        if (-not $base) { $base = Get-PimMapEdgeBase -Kind $EdgeKind }
        if (-not $base) {
            return [ordered]@{ ok = $false; mode = 'edge'; selection = "$EdgeKind"; destructive = $true; removedCount = 0; plans = @(); reasons = @("This edge ($EdgeKind) is not a removable assignment grant.") }
        }
        $cur = @()
        if ($CurrentRows.ContainsKey($base)) { $cur = @($CurrentRows[$base]) }
        foreach ($r in $cur) {
            if (Test-PimMapRowMatchesEdge -Base $base -Row $r -Match $EdgeMatch) { & $addRemoval $base $r }
        }
        if ($plansByBase.Count -eq 0) {
            [void]$reasons.Add("No row in $base matched the selected grant (it may already be removed).")
        }
        $selLabel = "$base"
    }
    else {
        # NODE: walk EVERY edge; any edge that references this node id maps (via its
        # kind) to an assignment base, and we drop the matching store row(s).
        $nid = "$NodeId".Trim()
        $edges = @($Data.edges)
        $matchedAny = $false
        foreach ($e in $edges) {
            $cosmetic = Get-PimMapNodeField -Node $e -Name 'cosmetic'
            if ($cosmetic -eq 'True' -or $cosmetic -eq $true) { continue }   # cosmetic edges own no row
            if (-not (Test-PimMapEdgeTouchesNode -Edge $e -NodeId $nid)) { continue }
            $ek = Get-PimMapNodeField -Node $e -Name 'kind'
            $base = Get-PimMapEdgeBase -Kind $ek
            if (-not $base) { continue }
            $ematch = $null
            if ($e -is [System.Collections.IDictionary]) { if ($e.Contains('match')) { $ematch = $e['match'] } }
            else { $mp = $e.PSObject.Properties['match']; if ($mp) { $ematch = $mp.Value } }
            if ($null -eq $ematch) { continue }
            $cur = @()
            if ($CurrentRows.ContainsKey($base)) { $cur = @($CurrentRows[$base]) }
            foreach ($r in $cur) {
                if (Test-PimMapRowMatchesEdge -Base $base -Row $r -Match $ematch) { & $addRemoval $base $r; $matchedAny = $true }
            }
        }
        if (-not $matchedAny) {
            [void]$reasons.Add("No assignment grant references node '$nid' (nothing to revoke).")
        }
        $selLabel = $nid
    }

    # Build the per-base after/removed sets. De-dupe removed rows by reference so a
    # node touched by two edges into the same row removes it once.
    $plans = New-Object System.Collections.ArrayList
    foreach ($base in @($plansByBase.Keys)) {
        $removed = @($plansByBase[$base])
        # de-dupe by identity (a row object may have been added twice)
        $seen = New-Object System.Collections.ArrayList
        $dedupRemoved = New-Object System.Collections.ArrayList
        foreach ($r in $removed) {
            $isNew = $true
            foreach ($s in $seen) { if ([object]::ReferenceEquals($s, $r)) { $isNew = $false; break } }
            if ($isNew) { [void]$seen.Add($r); [void]$dedupRemoved.Add($r) }
        }
        $removed = @($dedupRemoved.ToArray())
        $cur = @()
        if ($CurrentRows.ContainsKey($base)) { $cur = @($CurrentRows[$base]) }
        $after = New-Object System.Collections.ArrayList
        foreach ($r in $cur) {
            $drop = $false
            foreach ($d in $removed) { if ([object]::ReferenceEquals($d, $r)) { $drop = $true; break } }
            if (-not $drop) { [void]$after.Add($r) }
        }
        $totalRemoved += @($removed).Count
        [void]$plans.Add([ordered]@{
            base         = $base
            mode         = 'replace'
            afterRows    = @($after.ToArray())
            removedRows  = @($removed)
            removedCount = @($removed).Count
        })
    }

    $ok = ($totalRemoved -gt 0)
    return [ordered]@{
        ok           = $ok
        mode         = $(if ($PSCmdlet.ParameterSetName -eq 'Edge') { 'edge' } else { 'node' })
        selection    = "$selLabel"
        destructive  = $true
        removedCount = $totalRemoved
        plans        = @($plans.ToArray())
        reasons      = @($reasons.ToArray())
    }
}
