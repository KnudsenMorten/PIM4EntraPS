# PIM4EntraPS -- resource approvers/owners: approval routing + access reviews.
# Dot-sourced by PIM-Functions.psm1 (uses PIM-ChangeQueue.ps1 + PIM-PortalAccess.ps1)
# and the pim-manager.
#
# A resource (definition) carries OWNERS (the Owners column). An owner -- or a
# portal-admin with the 'approve-assignment' / 'access-review' capability in scope
# -- can APPROVE assignment requests to that resource and run ACCESS REVIEWS over
# its current assignments. Managing their consultants reuses the self-service
# toggle (PIM-Onboarding.ps1). Pure decision functions (testable); results feed
# the change queue.

Set-StrictMode -Off

function Get-PimResourceOwners {
    # Owners column -> array of identities (split on ; or , ; trimmed).
    param([Parameter(Mandatory)][object]$Row)
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('Owners')) { $v = "$($Row['Owners'])" } }
    else { $p = $Row.PSObject.Properties['Owners']; if ($p) { $v = "$($p.Value)" } }
    if (-not "$v".Trim()) { return @() }
    return @($v -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-PimIsResourceOwner {
    param([Parameter(Mandatory)][object]$Row, [Parameter(Mandatory)][string]$Identity)
    $owners = @(Get-PimResourceOwners -Row $Row | ForEach-Object { $_.ToLowerInvariant() })
    return ($owners -contains "$Identity".Trim().ToLowerInvariant())
}

# --- APPROVER MATRIX: dimensional approver routing (workload x tier x level x plane) ---
# Different people approve different slices: helpdesk mgr -> Entra roles L2; Power BI
# owner -> Power BI admin L1; etc. A rule:
#   @{ workload='Entra-ID'; tier=0; level=2; plane='*'; approvers=@('helpdeskmgr@..');
#      escalateTo=@('itmanager@..'); slaHours=24 }
# Blank/'*' on a dimension = any. Most-specific matching rule wins. Config key
# 'ApproverMatrix' (lives in SQL settings / config file seed).
function Get-PimApproverMatrix {
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { return @(Get-PimPolicySetting -Name 'ApproverMatrix' -Default @()) }
    if ($global:PIM_ApproverMatrix) { return @($global:PIM_ApproverMatrix) }
    return @()
}

function Test-PimApproverRuleMatch {
    # Returns the specificity (count of explicitly-set, matching dimensions) or -1
    # when the rule does not match these facets.
    param([Parameter(Mandatory)][object]$Rule, [Parameter(Mandatory)][hashtable]$Facets)
    $spec = 0
    $wl = "$($Rule.workload)".Trim()
    if ($wl -and $wl -ne '*') {
        if ("$wl" -ine "$($Facets.workload)" -and "$wl" -ine "$($Facets.service)") { return -1 }
        $spec++
    }
    if ($null -ne $Rule.tier -and "$($Rule.tier)" -ne '' -and "$($Rule.tier)" -ne '*') {
        if ([int]$Rule.tier -ne [int]$Facets.tier) { return -1 }; $spec++
    }
    if ($null -ne $Rule.level -and "$($Rule.level)" -ne '' -and "$($Rule.level)" -ne '*') {
        if ([int]$Rule.level -ne [int]$Facets.level) { return -1 }; $spec++
    }
    $pl = "$($Rule.plane)".Trim()
    if ($pl -and $pl -ne '*') { if ("$pl" -ine "$($Facets.plane)") { return -1 }; $spec++ }
    return $spec
}

function Get-PimMatchedApproverRule {
    # The most-specific matching rule for these facets, or $null.
    param([Parameter(Mandatory)][hashtable]$Facets, [object[]]$Matrix)
    if (-not $Matrix) { $Matrix = Get-PimApproverMatrix }
    $best = $null; $bestSpec = -1
    foreach ($r in @($Matrix)) {
        $s = Test-PimApproverRuleMatch -Rule $r -Facets $Facets
        if ($s -ge 0 -and $s -gt $bestSpec) { $best = $r; $bestSpec = $s }
    }
    return $best
}

function Get-PimApproversForResource {
    # Union of the matched matrix rule's approvers + the resource's Owners column.
    param([Parameter(Mandatory)][hashtable]$Facets, [object]$Row, [object[]]$Matrix)
    $set = New-Object System.Collections.Generic.List[string]
    $rule = Get-PimMatchedApproverRule -Facets $Facets -Matrix $Matrix
    if ($rule) { foreach ($a in @($rule.approvers)) { if ("$a".Trim()) { $set.Add("$a") } } }
    if ($Row) { foreach ($o in @(Get-PimResourceOwners -Row $Row)) { $set.Add("$o") } }
    return @($set.ToArray() | Select-Object -Unique)
}

function Get-PimEscalationApprovers {
    # The next-level (escalateTo) approvers for these facets (e.g. IT manager).
    param([Parameter(Mandatory)][hashtable]$Facets, [object[]]$Matrix)
    $rule = Get-PimMatchedApproverRule -Facets $Facets -Matrix $Matrix
    if ($rule) { return @(@($rule.escalateTo) | Where-Object { "$_".Trim() }) }
    return @()
}

function Test-PimApprovalEscalationDue {
    # Optional escalation: TRUE when the SLA (rule slaHours, default 24) has elapsed
    # since the request and it is still pending -> notify the escalateTo approvers.
    param([Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][datetime]$NowUtc, [int]$SlaHours = 24)
    if ("$($Request.status)" -ne 'pending') { return $false }
    $req = [datetime]::MinValue
    if (-not [datetime]::TryParse("$($Request.requestedUtc)", [ref]$req)) { return $false }
    return (($NowUtc - $req.ToUniversalTime()).TotalHours -ge $SlaHours)
}

function Test-PimCanApprove {
    # May $Identity approve assignments to this resource? Super-admin, OR a listed
    # OWNER, OR an APPROVER from the matrix (workload/tier/level/plane), OR a portal-
    # admin with 'approve-assignment' who can see the resource.
    param(
        [Parameter(Mandatory)][string]$Identity, [Parameter(Mandatory)][object]$Row,
        [AllowNull()][object]$Profile, [hashtable]$Facets, [object[]]$Matrix, [switch]$IsSuperAdmin
    )
    if ($IsSuperAdmin) { return $true }
    if (Test-PimIsResourceOwner -Row $Row -Identity $Identity) { return $true }
    $f = if ($Facets) { $Facets } else { Get-PimGroupFacets -Row $Row }
    $approvers = @(Get-PimApproversForResource -Facets $f -Row $Row -Matrix $Matrix | ForEach-Object { "$_".ToLowerInvariant() })
    if ($approvers -contains "$Identity".Trim().ToLowerInvariant()) { return $true }
    if ($Profile) {
        $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
        if ($caps -contains 'approve-assignment' -and (Test-PimPortalCanSeeGroup -Profile $Profile -Facets $f)) { return $true }
    }
    return $false
}

function New-PimApprovalRequest {
    # An assignment request awaiting an owner/approver decision.
    param(
        [Parameter(Mandatory)][string]$Requestor, [Parameter(Mandatory)][string]$TargetAdmin,
        [Parameter(Mandatory)][string]$GroupTag, [string]$Justification, [datetime]$NowUtc = [datetime]::UtcNow
    )
    return [pscustomobject]@{
        id = [guid]::NewGuid().ToString(); requestor = "$Requestor"; targetAdmin = "$TargetAdmin"
        groupTag = "$GroupTag"; justification = "$Justification"; requestedUtc = $NowUtc.ToString('o'); status = 'pending'
    }
}

function Resolve-PimApprovalDecision {
    # Decide an approval. $CanApprove is the gate result (Test-PimCanApprove).
    # approve -> status approved + a change-queue Create on PIM-Assignments-Admins;
    # reject -> status rejected, no change; not authorised -> ok=$false.
    param(
        [Parameter(Mandatory)][object]$Request, [Parameter(Mandatory)][string]$Approver,
        [Parameter(Mandatory)][ValidateSet('approve','reject')][string]$Decision,
        [Parameter(Mandatory)][bool]$CanApprove, [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not $CanApprove) { return [pscustomobject]@{ ok = $false; status = "$($Request.status)"; change = $null; reason = "$Approver is not an approver/owner for '$($Request.groupTag)'" } }
    if ($Decision -eq 'reject') { return [pscustomobject]@{ ok = $true; status = 'rejected'; change = $null; reason = 'rejected by approver' } }
    $key = "$($Request.targetAdmin)|$($Request.groupTag)"
    $change = New-PimChange -Entity 'PIM-Assignments-Admins' -Key $key -Op Create -By $Approver -Payload ([pscustomobject]@{ Username = "$($Request.targetAdmin)"; GroupTag = "$($Request.groupTag)"; ApprovedBy = $Approver; ApprovedUtc = $NowUtc.ToString('o') })
    return [pscustomobject]@{ ok = $true; status = 'approved'; change = $change; reason = 'approved' }
}

function Get-PimAccessReviewSet {
    # The assignments an OWNER must review: those whose GroupTag belongs to a
    # resource (definition) the owner owns. $Assignments = PIM-Assignments-Admins
    # rows (Username, GroupTag); $Definitions = definition rows (GroupTag, Owners).
    param(
        [object[]]$Assignments = @(), [Parameter(Mandatory)][string]$OwnerIdentity, [object[]]$Definitions = @()
    )
    $ownedTags = @{}
    foreach ($d in @($Definitions)) {
        if (Test-PimIsResourceOwner -Row $d -Identity $OwnerIdentity) {
            $tag = if ($d -is [System.Collections.IDictionary]) { "$($d['GroupTag'])" } else { "$($d.GroupTag)" }
            if ("$tag".Trim()) { $ownedTags["$tag".ToLowerInvariant()] = $true }
        }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Assignments)) {
        $tag = if ($a -is [System.Collections.IDictionary]) { "$($a['GroupTag'])" } else { "$($a.GroupTag)" }
        if ($ownedTags.ContainsKey("$tag".ToLowerInvariant())) { $out.Add($a) }
    }
    return $out.ToArray()
}

function Resolve-PimAccessReviewDecision {
    # An owner's per-assignment review decision. 'remove' -> a change-queue Remove
    # on PIM-Assignments-Admins; 'keep' -> no change.
    param(
        [Parameter(Mandatory)][object]$Assignment, [Parameter(Mandatory)][ValidateSet('keep','remove')][string]$Decision, [string]$By = "$env:USERNAME"
    )
    if ($Decision -eq 'keep') { return [pscustomobject]@{ change = $null; action = 'keep' } }
    $u = if ($Assignment -is [System.Collections.IDictionary]) { "$($Assignment['Username'])" } else { "$($Assignment.Username)" }
    $g = if ($Assignment -is [System.Collections.IDictionary]) { "$($Assignment['GroupTag'])" } else { "$($Assignment.GroupTag)" }
    $change = New-PimChange -Entity 'PIM-Assignments-Admins' -Key "$u|$g" -Op Remove -By $By
    return [pscustomobject]@{ change = $change; action = 'remove' }
}
