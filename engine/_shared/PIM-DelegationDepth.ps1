# PIM4EntraPS -- delegation DEPTH: local self-delegation, the two-approval split
# (delegation/assignment approval vs Entra-native activation approval), and
# reachability-by-classification. Dot-sourced by PIM-Functions.psm1 AFTER
# PIM-PortalAccess.ps1 + PIM-Approvals.ps1 (it builds on Get-PimGroupFacets,
# Get-PimApproverLayers, Resolve-PimApproverTokens, Get-PimPolicySetting).
#
# Pure + time-free decision functions -> fully testable offline. NOTHING here
# sends mail or writes to Entra/Azure; the engine/Manager consume the decisions.
#
# THE TWO-APPROVAL MODEL (REQUIREMENTS.md §13 / §25e) -- kept strictly distinct:
#
#   1. DELEGATION / ASSIGNMENT approval  (engine/GUI-owned, OUR workflow)
#        When an admin is ASSIGNED to a group and that assignment needs approval,
#        the engine/GUI routes the request to the approver. The approval is owned
#        by the GROUP, whose owner is EITHER a department OR a specific person.
#        A DEPARTMENT is allowed here -- the engine ENUMERATES the department's
#        owner (Owners -> SponsorUpn -> Department contact). Produced by
#        Get-PimDelegationApprovalPlan (it may carry '@Persona' and department-
#        derived people, resolved through Resolve-PimApproverTokens).
#
#   2. ACTIVATION approval  (Entra-PIM-native, NOT ours)
#        Happens user-side at activation; enforced 100% by the Entra PIM service
#        per the role-management policy. Entra PIM does NOT accept a department as
#        approver -- it must be specific PEOPLE. Our engine only DEPLOYS that
#        policy; it NEVER mediates activation and NEVER sends an activation email.
#        Get-PimActivationApprovalPeople produces the PEOPLE-ONLY approver set for
#        the policy: every department/persona is resolved to its owner people, and
#        a row that resolves to nothing is reported (so the engine can refuse to
#        ship an empty activation approval rule).

Set-StrictMode -Off

# --- 1. LOCAL SELF-DELEGATION --------------------------------------------------
# Local IT on the LOCAL plane self-delegates ANY permission (incl. privileged)
# with no MSP request (REQUIREMENTS.md §10 + §4 "local plane fully autonomous;
# Owner tag = provenance not a gate"). The ONLY gate is the deployment plane:
#   - local  : self-delegation always allowed (full local autonomy).
#   - msp    : self-delegation NOT allowed (the customer pulls baseline; an MSP
#              admin does not self-grant into a customer tenant).
# Plus the opt-in `Enforced` baseline keys (§25e): a customer/MSP may mark a
# specific groupTag `Enforced` so even a local admin cannot self-override it.
# Super-admins are NEVER locked out (break-glass). Pure: plane + facets in,
# decision out.

function Get-PimDelegationPlane {
    # The current deployment plane: 'local' (default, full autonomy) or 'msp'.
    # Config key 'DelegationPlane' (SQL settings / config / env PIM_DelegationPlane).
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $p = Get-PimPolicySetting -Name 'DelegationPlane' -Default 'local'
    } else { $p = $env:PIM_DelegationPlane; if (-not $p) { $p = 'local' } }
    $p = "$p".Trim().ToLowerInvariant()
    if ($p -ne 'msp') { return 'local' }   # anything not explicitly 'msp' = local
    return 'msp'
}

function Get-PimEnforcedBaselineTags {
    # Opt-in (default empty): groupTags an MSP/customer marked `Enforced` so a local
    # admin may NOT self-override them. Config key 'EnforcedBaselineTags' (array).
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $v = Get-PimPolicySetting -Name 'EnforcedBaselineTags' -Default @()
    } else { $v = $global:PIM_EnforcedBaselineTags }
    return @(@($v) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
}

function Test-PimSelfDelegationAllowed {
    # Can this requestor self-delegate the permission described by $Facets WITHOUT
    # going through an MSP/approval request?
    #   - SuperAdmin: always (break-glass; never locked out).
    #   - plane 'msp': never (no self-grant into a customer tenant from the MSP).
    #   - plane 'local': yes, for any permission/tier/level (full local autonomy)
    #       UNLESS the group's tag is in the Enforced baseline set.
    # $Plane is the DEPLOYMENT plane ('local'/'msp'), distinct from a group's
    # control-plane facet ('CP'/'MP'/'WDP'). Returns a result object with .allowed
    # + .reason so the Manager can show WHY.
    param(
        [Parameter(Mandatory)][hashtable]$Facets,
        [switch]$IsSuperAdmin,
        [string]$Plane,
        [object[]]$EnforcedTags
    )
    if ($IsSuperAdmin) { return [pscustomobject]@{ allowed = $true; reason = 'super-admin (never locked out)' } }
    if (-not $Plane) { $Plane = Get-PimDelegationPlane }
    $Plane = "$Plane".Trim().ToLowerInvariant()
    if ($Plane -eq 'msp') {
        return [pscustomobject]@{ allowed = $false; reason = 'msp plane: self-delegation goes through the customer baseline pull, not a self-grant' }
    }
    if ($null -eq $EnforcedTags) { $EnforcedTags = Get-PimEnforcedBaselineTags }
    $enf = @(@($EnforcedTags) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $tag = "$($Facets.groupTag)".Trim().ToLowerInvariant()
    if ($enf.Count -gt 0 -and $tag -and ($enf -contains $tag)) {
        return [pscustomobject]@{ allowed = $false; reason = "'$($Facets.groupTag)' is an Enforced baseline key (local override refused)" }
    }
    return [pscustomobject]@{ allowed = $true; reason = 'local plane: full local autonomy (Owner tag is provenance, not a gate)' }
}

function New-PimSelfDelegationChange {
    # A self-delegation materialises as a normal assignment change (the SAME entity
    # the approval workflow writes), NOT a privileged side-door -- so audit/offboard
    # treat it identically. Caller passes the gate result; we never re-decide here.
    param(
        [Parameter(Mandatory)][string]$Requestor,
        [Parameter(Mandatory)][string]$GroupTag,
        [Parameter(Mandatory)][bool]$Allowed,
        [string]$Justification = 'local self-delegation',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not $Allowed) { return [pscustomobject]@{ ok = $false; change = $null; reason = 'self-delegation not allowed for this plane/key' } }
    $payload = [pscustomobject]@{ Username = "$Requestor"; GroupTag = "$GroupTag"; SelfDelegated = $true; Justification = "$Justification"; RequestedUtc = $NowUtc.ToString('o') }
    $change = $null
    if (Get-Command New-PimChange -ErrorAction SilentlyContinue) {
        $change = New-PimChange -Entity 'PIM-Assignments-Admins' -Key "$Requestor|$GroupTag" -Op Create -By $Requestor -Payload $payload
    }
    return [pscustomobject]@{ ok = $true; change = $change; reason = 'self-delegated (local autonomy)' }
}

# --- 2. THE TWO-APPROVAL SPLIT -------------------------------------------------
# Departments may approve our DELEGATION workflow (enumerated to owners), but the
# Entra ACTIVATION policy must carry PEOPLE only.

function Get-PimDelegationApprovalPlan {
    # APPROVAL #1 (engine-owned, group-owned). Who the engine/GUI routes a
    # DELEGATION/ASSIGNMENT approval to, as ordered LAYERS (most-specific first),
    # built on the §13 approver matrix + the resource Owners. A department-derived
    # owner is fine here (it has already been enumerated into the Owners/approver
    # set upstream via Resolve-PimGroupOwnerIds / the dept contact). This is OUR
    # workflow -- it can escalate, remind, and time out.
    #   Returns: @{ kind='delegation'; layers=@(...); primary=@(...); escalation=@(...) }
    param([Parameter(Mandatory)][hashtable]$Facets, [object]$Row, [object[]]$Matrix)
    $layers  = @(Get-PimApproverLayers -Facets $Facets -Row $Row -Matrix $Matrix)
    $primary = if ($layers.Count) { @($layers[0].approvers) } else { @() }
    $esc     = @()
    if (Get-Command Get-PimEscalationApprovers -ErrorAction SilentlyContinue) { $esc = @(Get-PimEscalationApprovers -Facets $Facets -Matrix $Matrix) }
    return [pscustomobject]@{
        kind       = 'delegation'
        owned_by   = 'engine'
        layers     = @($layers)
        primary    = @($primary)
        escalation = @($esc)
    }
}

function Resolve-PimDepartmentPeople {
    # Resolve a department TOKEN (a name, or '@Persona', or a 'dept:Name' marker)
    # to its owner PEOPLE via the Departments contact index (+ SupportFunctions for
    # personas). Used to turn the activation approver set into people-only. Returns
    # @() when nothing resolves. Pure given the dept index ($DeptIndex: lowercased
    # dept -> Owners string); if omitted it pulls Get-PimDepartmentOwnerIndex.
    param([string]$Token, [hashtable]$DeptIndex)
    $t = "$Token".Trim()
    if (-not $t) { return @() }
    if ($t.StartsWith('dept:')) { $t = $t.Substring(5).Trim() }
    if ($null -eq $DeptIndex) {
        if (Get-Command Get-PimDepartmentOwnerIndex -ErrorAction SilentlyContinue) { $DeptIndex = Get-PimDepartmentOwnerIndex } else { $DeptIndex = @{} }
    }
    $key = $t.ToLowerInvariant()
    if ($DeptIndex.ContainsKey($key)) {
        $raw = $DeptIndex[$key]
        if (Get-Command Split-PimOwners -ErrorAction SilentlyContinue) { return @(Split-PimOwners $raw) }
        return @("$raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    return @()
}

function Test-PimLooksLikePerson {
    # A crude but safe people-vs-department test for the activation policy: a person
    # is an email/UPN (has '@' and a dot in the domain) OR an explicit object id
    # (GUID). Anything else (a bare department name, an unresolved '@Persona') is
    # NOT a person and must be resolved before it reaches the Entra policy.
    param([string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $false }
    if ($v -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $true }   # object id
    if ($v.StartsWith('@')) { return $false }   # unresolved persona token
    if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $true }   # upn/email
    return $false
}

function Get-PimActivationApprovalPeople {
    # APPROVAL #2 (Entra-native ACTIVATION policy). The PEOPLE-ONLY approver set the
    # engine writes into the role-management policy. Entra PIM refuses a department
    # as approver, so:
    #   1. expand '@Persona' tokens (SupportFunctions) to people,
    #   2. resolve any department token to its owner people (Departments contacts),
    #   3. DROP anything that still isn't a person, recording it in .unresolved.
    # Returns @{ people=@(unique upns/ids); unresolved=@(tokens that didn't resolve);
    #            ok=(people.Count -gt 0) }.
    # The engine MUST refuse to ship an approval-required activation policy when
    # people is empty (mirrors GroupsPolicies' existing "NO approver resolved" throw).
    param(
        [string[]]$Approvers,
        [hashtable]$DeptIndex
    )
    $people     = New-Object System.Collections.Generic.List[string]
    $unresolved = New-Object System.Collections.Generic.List[string]
    # First, expand personas to whatever they point at (may be people or depts).
    $expanded = @($Approvers)
    if (Get-Command Resolve-PimApproverTokens -ErrorAction SilentlyContinue) { $expanded = @(Resolve-PimApproverTokens -Approvers @($Approvers)) }
    foreach ($a in @($expanded)) {
        $t = "$a".Trim(); if (-not $t) { continue }
        if (Test-PimLooksLikePerson -Value $t) { $people.Add($t); continue }
        # Not a person yet -> try department resolution.
        $dp = @(Resolve-PimDepartmentPeople -Token $t -DeptIndex $DeptIndex)
        $got = $false
        foreach ($p in $dp) { if (Test-PimLooksLikePerson -Value $p) { $people.Add($p); $got = $true } }
        if (-not $got) { $unresolved.Add($t) }
    }
    $uniq = @($people.ToArray() | Where-Object { "$_".Trim() } | Select-Object -Unique)
    return [pscustomobject]@{
        people     = @($uniq)
        unresolved = @($unresolved.ToArray() | Select-Object -Unique)
        ok         = ($uniq.Count -gt 0)
    }
}

function Get-PimApprovalModelSummary {
    # One call that returns BOTH approval surfaces side-by-side for a resource, so a
    # caller (Manager preview, validator, engine policy build) never confuses them:
    #   .delegation  = engine-owned plan (departments allowed, layered/escalating)
    #   .activation  = Entra-native people-only set for the policy (+ unresolved)
    # The activation people are derived from ALL layers' approvers + the resource
    # owners (the same superset the policy would carry), resolved to people.
    param([Parameter(Mandatory)][hashtable]$Facets, [object]$Row, [object[]]$Matrix, [hashtable]$DeptIndex)
    $deleg = Get-PimDelegationApprovalPlan -Facets $Facets -Row $Row -Matrix $Matrix
    $allApprovers = New-Object System.Collections.Generic.List[string]
    foreach ($L in @($deleg.layers)) { foreach ($a in @($L.approvers)) { if ("$a".Trim()) { $allApprovers.Add("$a") } } }
    $act = Get-PimActivationApprovalPeople -Approvers @($allApprovers.ToArray()) -DeptIndex $DeptIndex
    return [pscustomobject]@{ delegation = $deleg; activation = $act }
}

# --- 3. REACHABILITY-BY-CLASSIFICATION -----------------------------------------
# How far a permission's NETWORK reach extends, by classification (tier/plane/
# level). REQUIREMENTS.md §10: tier-1/MP limited; tier-1/WDP/L3+ whole-network;
# configurable. This is the access-path/segmentation classification that pairs
# with the PAW gate (PIM-PortalAccess.ps1) -- PAW says "from which device", this
# says "to how much of the network". Fully overridable via $global:PIM_ReachPolicy.
#
# PAW DETECTION IS OPT-IN AND DEFAULTS TO OFF (REQUIREMENTS.md §10 / §22:
# "security tight but customizable to maturity; tight is NOT the default;
# PAW/tier-0 opt-in"). When detection is OFF (the default), reachability does NOT
# restrict anything to the PAW segment -- every classification resolves to
# 'whole-network' (the permissive, default-maturity path; no PAW-based deny).
# When a customer opts in ($global:PIM_PawDetection / PawDetection = $true) the
# segmentation policy applies (T0 -> paw-only, T1/MP -> limited, ...). This is a
# PERMANENT maturity toggle, NOT a debug/stopgap knob. Super-admins are never
# locked out regardless (Test-PimReachAllowed treats a super-admin as reach-anywhere).

function Test-PimPawDetectionEnabled {
    # Is PAW detection / reachability-restriction turned ON? OPT-IN: defaults to
    # $false so a fresh/low-maturity tenant gets the permissive whole-network path
    # and is never confined to a PAW segment it may not even have. A customer turns
    # it on via $global:PIM_PawDetection (or the PawDetection config key / env
    # PIM_PawDetection); $global:PIM_EnforcePaw is honoured as a synonym so one
    # switch can govern both the device PAW gate (PIM-PortalAccess.ps1
    # PawEnforcement) and reachability. Pure given config.
    param([Nullable[bool]]$Enabled)
    if ($null -ne $Enabled) { return [bool]$Enabled }
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $v = Get-PimPolicySetting -Name 'PawDetection' -Default $null
        if ($null -eq $v) { $v = Get-PimPolicySetting -Name 'EnforcePaw' -Default $null }
    } else {
        $v = $global:PIM_PawDetection
        if ($null -eq $v) { $v = $global:PIM_EnforcePaw }
    }
    if ($null -eq $v -or "$v".Trim() -eq '') { return $false }   # OFF by default (opt-in)
    return [bool]$v
}

function Get-PimDefaultReachPolicy {
    # First-match-wins rules: each maps (tier, plane, minLevel/maxLevel) -> a reach
    # class. Classes:
    #   'paw-only'      most restricted -- only the privileged/PAW segment (tier-0).
    #   'limited'       a constrained segment (tier-1 management plane).
    #   'whole-network' unrestricted within the corp network (tier-1 WDP/L3+, tier-2).
    # Default reflects the spec: T0 -> paw-only; T1/MP -> limited; T1/WDP L3+ and
    # everything less privileged -> whole-network.
    return @(
        @{ tier = 0;                              reach = 'paw-only' }
        @{ tier = 1; plane = 'MP';                reach = 'limited' }
        @{ tier = 1; plane = 'WDP'; minLevel = 3; reach = 'whole-network' }
    )
}

function Resolve-PimReachability {
    # The reach class a (tier, plane, level) is allowed, per policy. Unmatched ->
    # 'whole-network' (least-restrictive default for low-privilege work; tighten via
    # policy). Returns a string class. Pure.
    #
    # PAW detection is OPT-IN (OFF by default): when it is OFF the segmentation is
    # not applied at all -- EVERY classification (incl. T0) resolves to
    # 'whole-network' so there is no PAW-based restriction. Pass -PawDetection to
    # force the decision (e.g. a super-admin is always treated as detection-off so a
    # blank/misdetected segment can never lock them out).
    param([Parameter(Mandatory)][int]$Tier, [string]$Plane, [int]$Level = 0, [object[]]$Policy, [Nullable[bool]]$PawDetection)
    if (-not (Test-PimPawDetectionEnabled -Enabled $PawDetection)) { return 'whole-network' }   # opt-in OFF (default) -> no PAW restriction
    if (-not $Policy) {
        if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $Policy = @(Get-PimPolicySetting -Name 'ReachPolicy' -Default (Get-PimDefaultReachPolicy)) }
        else { $Policy = Get-PimDefaultReachPolicy }
    }
    foreach ($r in @($Policy)) {
        if ($null -ne $r.tier -and "$($r.tier)" -ne '' -and "$($r.tier)" -ne '*' -and [int]$r.tier -ne $Tier) { continue }
        if ("$($r.plane)".Trim() -and "$($r.plane)" -ne '*' -and "$($r.plane)" -ine "$Plane") { continue }
        if ($null -ne $r.minLevel -and "$($r.minLevel)" -ne '' -and $Level -lt [int]$r.minLevel) { continue }
        if ($null -ne $r.maxLevel -and "$($r.maxLevel)" -ne '' -and $Level -gt [int]$r.maxLevel) { continue }
        $c = "$($r.reach)".Trim()
        if ($c) { return $c }
    }
    return 'whole-network'
}

function Get-PimReachabilityForGroup {
    # Convenience: reach class straight from a definition ROW (via Get-PimGroupFacets).
    # PAW detection is opt-in (OFF by default) -> a row resolves to 'whole-network'
    # unless detection is enabled (see Resolve-PimReachability). -PawDetection forces
    # the decision for tests / a super-admin caller.
    param([Parameter(Mandatory)][object]$Row, [object[]]$Policy, [Nullable[bool]]$PawDetection)
    $f = Get-PimGroupFacets -Row $Row
    $tier  = if ($null -ne $f.tier)  { [int]$f.tier }  else { 2 }    # unknown -> least privileged
    $level = if ($null -ne $f.level) { [int]$f.level } else { 0 }
    return (Resolve-PimReachability -Tier $tier -Plane "$($f.plane)" -Level $level -Policy $Policy -PawDetection $PawDetection)
}

function Test-PimReachAllowed {
    # Is a request whose effective device/segment reach is $RequestReach permitted to
    # manage a group classified at $RequiredReach? Ordering (more restricted first):
    #   paw-only < limited < whole-network. A request from a MORE restricted segment
    #   (paw-only) may reach anything; a request from a LESS restricted segment may
    #   NOT reach a more-restricted classification. Mirrors the PAW "lower level may
    #   manage higher" rule, applied to network reach. Pure.
    #
    # Super-admins are NEVER locked out (break-glass): -IsSuperAdmin always returns
    # $true so a blank/misdetected segment can't strand them. Also, when PAW
    # detection is OFF (the opt-in default) there is no reach restriction at all.
    param([Parameter(Mandatory)][string]$RequiredReach, [Parameter(Mandatory)][string]$RequestReach, [switch]$IsSuperAdmin, [Nullable[bool]]$PawDetection)
    if ($IsSuperAdmin) { return $true }                                   # break-glass: never locked out
    if (-not (Test-PimPawDetectionEnabled -Enabled $PawDetection)) { return $true }   # opt-in OFF (default) -> no restriction
    $rank = @{ 'paw-only' = 0; 'limited' = 1; 'whole-network' = 2 }
    $req = if ($rank.ContainsKey("$RequiredReach".ToLowerInvariant())) { $rank["$RequiredReach".ToLowerInvariant()] } else { 2 }
    $have = if ($rank.ContainsKey("$RequestReach".ToLowerInvariant())) { $rank["$RequestReach".ToLowerInvariant()] } else { 2 }
    return ($have -le $req)
}
