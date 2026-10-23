#Requires -Version 5.1
<#
.SYNOPSIS
    Tier-impact report -- PURE, offline, unit-testable. (REQUIREMENTS §23,
    ROADMAP #24: "every user with any path (incl. indirect via nested groups)
    to T0/T1 assets, computed from the graph reach analysis".)

.DESCRIPTION
    One pure function over the SAME node/edge model the Delegation Map renders
    (Build-PimGraphData / Get-PimAccessGraphModel). No SQL, no Graph, no HTTP --
    everything is computed from the in-memory model so it can be seeded + tested
    offline and reused by the server endpoint.

      Get-PimTierImpactReport -- for EVERY admin (principal) in the model, walk
                                 the live delegation graph forward (admin ->
                                 role group -> nested permission group(s) ->
                                 target) and determine the MOST PRIVILEGED tier
                                 the admin can reach. Returns one row per admin
                                 who reaches ANY Tier-0/Tier-1 target, with:
                                   * the highest tier reached (T0 beats T1)
                                   * how many distinct T0/T1 targets they reach
                                   * the granting path to the WORST (highest)
                                     target (admin -> group(s) -> target)
                                   * whether the worst path is through a NESTED
                                     (indirect) group -- the thing a flat role
                                     list misses.

    TIER OF A REACHED TARGET -- a synthetic target node (entra-role / au-role /
    az-resource) carries no tier of its own, so its effective tier is inherited
    from the GROUPS that grant it (a role/permission group carries a LEVEL and a
    TIER via the naming convention -- L0..L9 and T0..T2, two separate markers).
    The tier of a PATH = the most privileged (lowest number) group TIER on that
    path, OR the target node's own tier marker when it carries one. The LEVEL is
    reported separately (highestLevel / highestLevelLabel) for display and never
    decides who is flagged (TIER-IMPACT-LEVEL-VS-TIER, owner 2026-10-23). This mirrors how the Delegation Map risk
    overlay (PIM-MapRisk.ps1) treats a reached group's own T0/T1 tier as a
    high-privilege signal -- here we attribute it to the SPECIFIC target + path.

    Reach semantics are IDENTICAL to PIM-MapRisk.ps1 / Get-PimAccessGraphModel:
    column-oriented (admin=0, role-group=1, permission-group=2, target=3), group
    nesting oriented low-col -> high-col, same-column nest dropped, cosmetic /
    au-to-au-role edges excluded. This lib REUSES the PIM-MapRisk helpers
    (Get-PimMapNodeField / Get-PimMapNodeLabel / Get-PimMapColumn /
    ConvertTo-PimMapReach) when they are already loaded, and defines a private
    fallback so it is self-contained when dot-sourced alone in a test.

    PowerShell 5.1 safe: no ?./??, no null-conditional, every node field read
    through a guarded accessor that never throws on a missing property; List[object]
    materialised with .ToArray() (never @()).
#>

# --- self-contained fallbacks (only define if PIM-MapRisk isn't loaded) --------
if (-not (Get-Command Get-PimMapNodeField -ErrorAction SilentlyContinue)) {
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
}
if (-not (Get-Command Get-PimMapNodeLabel -ErrorAction SilentlyContinue)) {
    function Get-PimMapNodeLabel {
        param($Node, [string]$Id)
        $lbl = Get-PimMapNodeField -Node $Node -Name 'label'
        if ("$lbl".Trim()) { return "$lbl" }
        return "$Id"
    }
}
if (-not (Get-Command Get-PimMapColumn -ErrorAction SilentlyContinue)) {
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
}
if (-not (Get-Command ConvertTo-PimMapReach -ErrorAction SilentlyContinue)) {
    function ConvertTo-PimMapReach {
        [CmdletBinding()]
        param([Parameter(Mandatory)]$Data)
        $nodes = @($Data.nodes); $edges = @($Data.edges)
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
        $fwd = @{}; $back = @{}
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
                if ($cs -eq $ct) { continue }
                if ($cs -gt $ct) { $tmp = $s; $s = $t; $t = $tmp }
            }
            if (-not $fwd.ContainsKey($s)) { $fwd[$s] = New-Object System.Collections.ArrayList }
            [void]$fwd[$s].Add($t)
            if (-not $back.ContainsKey($t)) { $back[$t] = New-Object System.Collections.ArrayList }
            [void]$back[$t].Add($s)
        }
        return @{ nodes = $nodes; byId = $byId; fwd = $fwd; back = $back }
    }
}

# --- TIER vs LEVEL (TIER-IMPACT-LEVEL-VS-TIER, owner 2026-10-23 "Fix it, ring 0/1") --
# The naming convention carries TWO separate markers: the LEVEL (-L<n>-, L0..L9, the
# delegation layer; an Azure level follows the CAF management-group layer) and the
# TIER (-T<n>-, T0..T2, the security tier). This report is about TIERS: who can reach
# a Tier-0 / Tier-1 target. It used to read the LEVEL and treat that number as the
# tier, so an L3-T1 group read as "T3" (not flagged) and an L0-T2 group read as "T0".
# Now:
#   * Get-PimTierImpactNodeTier  -- the TIER: an explicit tier field wins, then the
#     -T<n>- marker. A level NEVER stands in for a tier: a node with no tier marker
#     is untiered for tier purposes (never flagged).
#   * Get-PimTierImpactNodeLevel -- the LEVEL (L0..L9), kept as a separate field for
#     display only. A tier never stands in for a level either.
function Get-PimTierImpactNodeCandidates {
    param($Node)
    $cand = New-Object System.Collections.ArrayList
    foreach ($k in 'groupTag','label','id') {
        $v = Get-PimMapNodeField -Node $Node -Name $k
        if ("$v".Trim()) { [void]$cand.Add("$v") }
    }
    return ,$cand
}

# The node's TIER (0..2; 0 = most privileged) or $null (untiered).
function Get-PimTierImpactNodeTier {
    param($Node)
    if ($null -eq $Node) { return $null }
    # 1. an explicit tier field ('T1' or '1') wins.
    $explicit = Get-PimMapNodeField -Node $Node -Name 'tier'
    if ("$explicit" -match '(?i)^\s*T?([0-2])\s*$') { return [int]$Matches[1] }
    $cand = Get-PimTierImpactNodeCandidates -Node $Node
    # 2. the -L<n>-T<n>- pair the naming convention writes (the T right after an L marker), then
    # 3. a lone -T<n>- marker. Checked across every candidate before falling to the lone marker,
    #    so a group TAG that happens to end in -T<n> never outranks the full name's pair.
    foreach ($c in $cand) {
        if ("$c" -match '(?i)(^|[-_.\s])L[0-9]+[-_.\s]T([0-2])([-_.\s]|$)') { return [int]$Matches[2] }
    }
    foreach ($c in $cand) {
        if ("$c" -match '(?i)(^|[-_.\s])T([0-2])([-_.\s]|$)') { return [int]$Matches[2] }
    }
    return $null
}

# The node's LEVEL (0..9) or $null -- display only, never used for flagging.
function Get-PimTierImpactNodeLevel {
    param($Node)
    if ($null -eq $Node) { return $null }
    $explicit = Get-PimMapNodeField -Node $Node -Name 'level'
    if ("$explicit" -match '(?i)^\s*L?([0-9])\s*$') { return [int]$Matches[1] }
    foreach ($c in (Get-PimTierImpactNodeCandidates -Node $Node)) {
        if ("$c" -match '(?i)(^|[-_.\s])L([0-9])([-_.\s]|$)') { return [int]$Matches[2] }
    }
    return $null
}

# A tier int -> a "T<n>" label for display (T0 most privileged). $null -> ''.
# (-Level kept as the parameter name for compatibility; the value is the TIER.)
function Get-PimTierImpactTierLabel {
    param([Alias('Tier')]$Level)
    if ($null -eq $Level) { return '' }
    return ("T{0}" -f [int]$Level)
}

# A level int -> an "L<n>" label for display. $null -> ''.
function Get-PimTierImpactLevelLabel {
    param($Level)
    if ($null -eq $Level) { return '' }
    return ("L{0}" -f [int]$Level)
}

function Get-PimTierImpactReport {
    [CmdletBinding()]
    param(
        # The Build-PimGraphData output ({ nodes=[]; edges=[]; tenantId; tenantName }).
        [Parameter(Mandatory)]$Data,
        # The tier ceiling that counts as "high impact". Default 1 = flag any admin
        # who can reach a Tier-0 OR Tier-1 target. (0 = Tier-0 only.)
        [int]$HighTierMax = 1
    )

    $model    = ConvertTo-PimMapReach -Data $Data
    $byId     = $model.byId
    $targetKinds = @('entra-role','au-role','az-resource')

    $isTarget = {
        param($Id)
        if ($byId.ContainsKey("$Id")) {
            return ($targetKinds -contains (Get-PimMapNodeField -Node $byId["$Id"] -Name 'kind'))
        }
        return $false
    }

    $admins = @($Data.nodes | Where-Object { (Get-PimMapNodeField -Node $_ -Name 'kind') -eq 'admin' })

    $rows = New-Object System.Collections.ArrayList
    $scannedAdmins = 0
    $totalHighTargetsAllAdmins = 0

    foreach ($a in $admins) {
        $aid = Get-PimMapNodeField -Node $a -Name 'id'
        if (-not "$aid".Trim()) { continue }
        $scannedAdmins++

        # BFS forward from the admin. Each queue item carries the running path of
        # node ids AND the most-privileged (minimum) group TIER seen ON that path
        # so far -- so when we hit a target we know the effective tier of the path
        # WITHOUT re-walking, and we keep the chain to show HOW it is granted. The
        # minimum LEVEL on the path rides along separately, for display only.
        $bestLevel = $null            # the most privileged TIER this admin reaches (min tier; name kept)
        $bestLvl   = $null            # the most privileged LEVEL on the worst path (display only)
        $bestPath  = $null            # the path ids to the worst target
        $bestTarget = $null           # the worst target node id
        $bestNested = $false          # is the worst path through a nested (perm) group?
        $highTargets = @{}            # distinct target ids at tier <= HighTierMax

        $q = New-Object System.Collections.Queue
        # start: at the admin, no group tier/level yet, path = [adminId]
        $q.Enqueue([ordered]@{ id = "$aid"; minLevel = $null; minLvl = $null; path = @("$aid"); nested = $false; visited = @{ "$aid" = $true } })
        $hops = 0
        while ($q.Count -gt 0 -and $hops -lt 20000) {
            $hops++
            $cur = $q.Dequeue()
            if (-not $model.fwd.ContainsKey($cur.id)) { continue }
            foreach ($nx in $model.fwd[$cur.id]) {
                $nxId   = "$nx"
                $nxNode = $null; if ($byId.ContainsKey($nxId)) { $nxNode = $byId[$nxId] }
                $nxKind = Get-PimMapNodeField -Node $nxNode -Name 'kind'
                $nxCol  = Get-PimMapColumn $nxKind

                # Carry the running most-privileged group TIER (and, separately, LEVEL).
                # A GROUP node on the path (role-group col1 / permission-group col2)
                # contributes its own tier/level; the admin + targets do not.
                $runMin = $cur.minLevel
                $runLvl = $cur.minLvl
                $isGroup = ($nxKind -eq 'role-group' -or $nxKind -eq 'permission-group')
                if ($isGroup) {
                    $tr = Get-PimTierImpactNodeTier -Node $nxNode
                    if ($null -ne $tr) {
                        if ($null -eq $runMin -or $tr -lt $runMin) { $runMin = $tr }
                    }
                    $lvl = Get-PimTierImpactNodeLevel -Node $nxNode
                    if ($null -ne $lvl) {
                        if ($null -eq $runLvl -or $lvl -lt $runLvl) { $runLvl = $lvl }
                    }
                }
                # Did we step THROUGH a nested (permission) group to get here? Col 2
                # is the nested permission-group tier -- the indirect path a flat
                # role list misses.
                $stepNested = $cur.nested -or ($nxCol -eq 2)

                $newPath = @($cur.path) + $nxId

                if (& $isTarget $nxId) {
                    # Effective tier of THIS path to THIS target = the most privileged
                    # of (the running group min level) and (the target's own marker,
                    # if any -- e.g. a target explicitly tagged T0). $effLevel is the TIER.
                    $tgtOwn = Get-PimTierImpactNodeTier -Node $nxNode
                    $effLevel = $runMin
                    if ($null -ne $tgtOwn) {
                        if ($null -eq $effLevel -or $tgtOwn -lt $effLevel) { $effLevel = $tgtOwn }
                    }
                    $tgtLvl = Get-PimTierImpactNodeLevel -Node $nxNode
                    $effLvl = $runLvl
                    if ($null -ne $tgtLvl) {
                        if ($null -eq $effLvl -or $tgtLvl -lt $effLvl) { $effLvl = $tgtLvl }
                    }
                    if ($null -ne $effLevel) {
                        if ($effLevel -le $HighTierMax) {
                            $highTargets[$nxId] = $true
                        }
                        # Track the WORST (most privileged) reachable target for the
                        # headline path. Tie-break: a nested path is the more
                        # interesting one to surface (it's the hidden reach).
                        $take = $false
                        if ($null -eq $bestLevel) { $take = $true }
                        elseif ($effLevel -lt $bestLevel) { $take = $true }
                        elseif ($effLevel -eq $bestLevel -and $stepNested -and -not $bestNested) { $take = $true }
                        if ($take) {
                            $bestLevel  = $effLevel
                            $bestLvl    = $effLvl
                            $bestPath   = $newPath
                            $bestTarget = $nxId
                            $bestNested = $stepNested
                        }
                    }
                    # A target is terminal -- do not walk past it.
                } else {
                    # Intermediate (group / AU) -- keep walking, cycle-safe.
                    if (-not $cur.visited.ContainsKey($nxId)) {
                        $nv = @{}; foreach ($k in $cur.visited.Keys) { $nv[$k] = $true }; $nv[$nxId] = $true
                        $q.Enqueue([ordered]@{ id = $nxId; minLevel = $runMin; minLvl = $runLvl; path = $newPath; nested = $stepNested; visited = $nv })
                    }
                }
            }
        }

        $highCount = @($highTargets.Keys).Count
        $totalHighTargetsAllAdmins += $highCount
        if ($highCount -gt 0 -and $null -ne $bestLevel -and $bestLevel -le $HighTierMax) {
            # Render the granting path to the worst target as labels.
            $pathLabels = New-Object System.Collections.ArrayList
            foreach ($pathId in @($bestPath)) {
                $pn = $null; if ($byId.ContainsKey("$pathId")) { $pn = $byId["$pathId"] }
                [void]$pathLabels.Add((Get-PimMapNodeLabel -Node $pn -Id "$pathId"))
            }
            $worstNode = $null; if ($byId.ContainsKey("$bestTarget")) { $worstNode = $byId["$bestTarget"] }
            [void]$rows.Add([ordered]@{
                person          = "$aid"
                displayName     = (Get-PimMapNodeLabel -Node $a -Id "$aid")
                purpose         = (Get-PimMapNodeField -Node $a -Name 'purpose')
                highestTier     = (Get-PimTierImpactTierLabel -Level $bestLevel)
                # highestTierLevel = the TIER number (0..2; name kept for the consumers: T0 = 0).
                highestTierLevel = [int]$bestLevel
                # The LEVEL (L0..L9) on the worst path, separately -- display only, never flagging.
                highestLevel      = $(if ($null -ne $bestLvl) { [int]$bestLvl } else { $null })
                highestLevelLabel = (Get-PimTierImpactLevelLabel -Level $bestLvl)
                highTargetCount = $highCount
                worstTarget     = "$bestTarget"
                worstTargetLabel = (Get-PimMapNodeLabel -Node $worstNode -Id "$bestTarget")
                worstTargetRole  = (Get-PimMapNodeField -Node $worstNode -Name 'roleName')
                viaNested       = [bool]$bestNested
                path            = @($pathLabels.ToArray())
                pathText        = (($pathLabels.ToArray()) -join ' -> ')
            })
        }
    }

    # Sort: most privileged first (T0 before T1), then most high-tier targets, then name.
    $sorted = @($rows | Sort-Object `
        @{ Expression = { [int]$_.highestTierLevel } }, `
        @{ Expression = { -1 * [int]$_.highTargetCount } }, `
        @{ Expression = { "$($_.displayName)".ToLowerInvariant() } })

    $t0 = @($sorted | Where-Object { [int]$_.highestTierLevel -eq 0 }).Count
    $t1 = @($sorted | Where-Object { [int]$_.highestTierLevel -eq 1 }).Count

    return [ordered]@{
        highTierMax       = $HighTierMax
        scannedAdmins     = $scannedAdmins
        impactedCount     = @($sorted).Count
        tier0Count        = $t0
        tier1Count        = $t1
        totalHighTargets  = $totalHighTargetsAllAdmins
        rows              = @($sorted)
        tenantId          = $(if ($Data.PSObject.Properties['tenantId']) { $Data.tenantId } elseif ($Data -is [System.Collections.IDictionary] -and $Data.Contains('tenantId')) { $Data['tenantId'] } else { '' })
        tenantName        = $(if ($Data.PSObject.Properties['tenantName']) { $Data.tenantName } elseif ($Data -is [System.Collections.IDictionary] -and $Data.Contains('tenantName')) { $Data['tenantName'] } else { '' })
        generatedUtc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}
