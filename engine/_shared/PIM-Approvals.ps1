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

function Test-PimCanApprove {
    # May $Identity approve assignments to this resource? Super-admin, OR a listed
    # OWNER of the resource, OR a portal-admin with 'approve-assignment' who can see
    # the resource (tier/level/service/scope via Test-PimPortalCanSeeGroup).
    param(
        [Parameter(Mandatory)][string]$Identity, [Parameter(Mandatory)][object]$Row,
        [AllowNull()][object]$Profile, [hashtable]$Facets, [switch]$IsSuperAdmin
    )
    if ($IsSuperAdmin) { return $true }
    if (Test-PimIsResourceOwner -Row $Row -Identity $Identity) { return $true }
    if ($Profile) {
        $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
        if ($caps -contains 'approve-assignment') {
            $f = if ($Facets) { $Facets } else { Get-PimGroupFacets -Row $Row }
            if (Test-PimPortalCanSeeGroup -Profile $Profile -Facets $f) { return $true }
        }
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
