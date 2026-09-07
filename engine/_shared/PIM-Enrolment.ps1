# =============================================================================================
# PIM-Enrolment.ps1 -- MSP-5, THE SLAVE-ENROLMENT HANDSHAKE ("the slave knocks on the door").
#
# The operator's shape: *"basic deployment of a slave with minimum config ... then the slave knock
# on the door to master. then master sends downstream allowed config like central admin accounts,
# central roles and assignments."*
#
# 🔴 WHAT IS GENUINELY NEW HERE IS THE **RETURN PATH**, and it is the reason this file is mostly
# refusals. Framework §8's uplink is APPEND-ONLY BY DESIGN: a customer POSTs its outcome and can
# read nothing back. "The slave knocks and receives its allowed config" adds a READ surface, which
# is a different capability with a different risk profile. The four decisions that had to be made
# before any of it could be built are recorded below, each next to the code that implements it.
#
# ---------------------------------------------------------------------------------------------
# FORK 1 -- ENROLMENT IS A TRUST DECISION, SO IT NEEDS AN MSP-SIDE APPROVAL GATE.
#   Without one, KNOCKING *IS* ENROLMENT: any tenant holding a valid token joins the fleet and
#   starts receiving central admin accounts. So a knock creates a REQUEST, never a relationship.
#   `Get-PimEnrolmentDecision` refuses anything that is not explicitly approved, and "unknown"
#   refuses exactly as loudly as "denied" -- an unrecognised tenant must never be the easy case.
#
# FORK 2 -- IT MUST NOT BECOME A SECOND DISTRIBUTION CHANNEL.
#   The signed baseline bundle exists so a customer can verify what it received WITHOUT trusting
#   the transport. A config-over-API path that returns config inline bypasses the guarantee it
#   replaces. So an approved knock returns a POINTER to the same signed artifact -- never the
#   artifacts themselves. `New-PimEnrolmentGrant` carries `bundleUri` + `keyThumbprint`, and there
#   is deliberately no field that could carry an admin, a role, or an assignment.
#
# FORK 3 -- MSP-3 STAYS INTACT: THE MASTER ANSWERS A REQUEST, IT NEVER REACHES IN.
#   Everything here is master-side evaluation of a document the slave sent. Nothing in this file
#   opens a connection to a managed tenant, and the grant it produces is something the SLAVE then
#   acts on with its own identity -- which is what the live proof established.
#
# FORK 4 -- THE JSON IS THE SOURCE OF TRUTH; A CLI SELECTS OR OVERRIDES IT, NEVER CONFIGURES.
#   The request IS a JSON document, and it round-trips (asserted). There is no second place where
#   an enrolment can be described.
#
# ◻ NOT BUILT HERE, ON PURPOSE: the transport. Framework §8.2's authenticated, append-only API in
#   the operator tenant belongs to SOLUTIONS/PlatformMonitoring. PIM builds the PAYLOAD and the
#   DECISION -- inventing a PIM-private inbound path from ~30 customers would bypass exactly the
#   reasoning that made §8.2 the estate's only one. This is the same split MSP-3 step 5 already
#   used for the acceptance record, and for the same reason.
#
# PS 5.1 COMPATIBLE: no ?./??, no ternary, Set-StrictMode -Off, null-guarded.
# =============================================================================================

Set-StrictMode -Off

function New-PimEnrolmentRequest {
    <#
      THE KNOCK. What a freshly-deployed slave sends: who it is, where it is, and what it is asking
      to become. PURE -- builds the document, sends nothing.

      🔒 It carries NO CREDENTIAL and NO SECRET. A knock is a claim of identity, not proof of one;
      the proof is the authenticated channel it arrives on (framework §8.2), and putting a secret in
      the body would make the document itself worth stealing.
      🪤 `requestedRing` is what the slave ASKS FOR, and the name says so. The ring it GETS is the
      operator's to decide -- a tenant that could choose its own ring could choose ring 0 and
      receive the earliest, least-proven baseline, which is the opposite of what rings are for.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$DisplayName,
        [int]$RequestedRing = 3,
        [string]$Scenario = '',
        [string]$SubscriptionId = '',
        [string]$UplinkUri = '',
        [string[]]$AdminAccountPrefixes = @(),
        [string]$Nonce = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $n = "$Nonce".Trim()
    if (-not $n) { $n = [guid]::NewGuid().ToString() }
    return [ordered]@{
        kind          = 'pim-enrolment-request'
        version       = 1
        tenantId      = "$TenantId".Trim()
        displayName   = "$DisplayName".Trim()
        # ASKED FOR, not granted. See the note above.
        requestedRing = [int]$RequestedRing
        scenario      = "$Scenario".Trim()
        subscriptionId = "$SubscriptionId".Trim()
        uplinkUri     = "$UplinkUri".Trim()
        # IMP-13: the slave declares its own admin naming conventions AT ENROLMENT, which is the
        # moment the mismatch is cheapest to fix -- before any account has been created in it.
        adminAccountPrefixes = @(@($AdminAccountPrefixes) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        nonce         = $n
        requestedAtUtc = $NowUtc.ToString('o')
    }
}

function Test-PimEnrolmentRequest {
    <#
      Is this knock even well-formed? Returns @{ ok; reason }. Shape only -- it says nothing about
      whether the tenant SHOULD be enrolled, which is Get-PimEnrolmentDecision's job and a
      different question entirely.
      🔒 Fails CLOSED on every missing field: a malformed request must not become an approved one
      by way of a default.
    #>
    [CmdletBinding()] param($Request)
    if ($null -eq $Request) { return [ordered]@{ ok = $false; reason = 'no request document' } }
    $kind = "$(Get-PimDownlinkValue -Object $Request -Key 'kind')".Trim()
    if ($kind -ne 'pim-enrolment-request') { return [ordered]@{ ok = $false; reason = "unexpected document kind '$kind' (expected pim-enrolment-request)" } }
    $tid = "$(Get-PimDownlinkValue -Object $Request -Key 'tenantId')".Trim()
    if (-not $tid) { return [ordered]@{ ok = $false; reason = 'the request names no tenantId' } }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($tid, [ref]$guid)) { return [ordered]@{ ok = $false; reason = "tenantId '$tid' is not a GUID" } }
    if (-not "$(Get-PimDownlinkValue -Object $Request -Key 'displayName')".Trim()) { return [ordered]@{ ok = $false; reason = 'the request names no displayName -- an operator approving it would be approving an id' } }
    if (-not "$(Get-PimDownlinkValue -Object $Request -Key 'nonce')".Trim()) { return [ordered]@{ ok = $false; reason = 'the request carries no nonce, so a replay could not be told from a retry' } }
    return [ordered]@{ ok = $true; reason = '' }
}

function Get-PimEnrolmentDecision {
    <#
      FORK 1 -- THE APPROVAL GATE, and the whole point of the handshake.

      🔴 DEFAULT IS REFUSE. An enrolment is a trust decision: it decides that a tenant will receive
      the MSP's central admin accounts, which is to say privileged identities. Anything not
      explicitly approved by the operator is refused, and an UNKNOWN tenant is refused with its own
      reason -- "we have never heard of you" and "we said no" are different facts and an operator
      reading a log needs to tell them apart.

      -Registry: the operator's decisions, @( @{ tenantId; state = approved|denied; ring } ).
      Returns @{ enrolled; state; ring; reason }.
      PURE.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Request,
        [AllowEmptyCollection()][object[]]$Registry = @()
    )
    $shape = Test-PimEnrolmentRequest -Request $Request
    if (-not $shape.ok) { return [ordered]@{ enrolled = $false; state = 'malformed'; ring = $null; reason = $shape.reason } }
    $tid = "$(Get-PimDownlinkValue -Object $Request -Key 'tenantId')".Trim().ToLowerInvariant()
    $hit = @(@($Registry) | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'tenantId')".Trim().ToLowerInvariant() -eq $tid })
    if (-not $hit.Count) {
        return [ordered]@{ enrolled = $false; state = 'unknown'; ring = $null
            reason = "tenant $tid has not been approved for enrolment -- knocking is not joining. An operator must approve it before the master will answer with anything." }
    }
    $state = "$(Get-PimDownlinkValue -Object $hit[0] -Key 'state')".Trim().ToLowerInvariant()
    if ($state -ne 'approved') {
        return [ordered]@{ enrolled = $false; state = $(if ($state) { $state } else { 'unknown' }); ring = $null
            reason = "tenant $tid is registered but not approved (state '$state')" }
    }
    # 🔒 THE RING IS THE OPERATOR'S, NOT THE REQUESTER'S. Taken from the registry entry, and the
    # requested ring is deliberately not consulted: a tenant that could pick its own ring could pick
    # the earliest, least-proven baseline, which inverts what rings exist to do.
    $ring = $null
    $rawRing = Get-PimDownlinkValue -Object $hit[0] -Key 'ring'
    if ($null -ne $rawRing -and "$rawRing".Trim() -ne '') { $ring = [int]"$rawRing" }
    if ($null -eq $ring) {
        return [ordered]@{ enrolled = $false; state = 'approved-without-ring'; ring = $null
            reason = "tenant $tid is approved but no ring was assigned -- refusing rather than defaulting, because a defaulted ring decides which baseline a customer receives" }
    }
    return [ordered]@{ enrolled = $true; state = 'approved'; ring = $ring; reason = '' }
}

function New-PimEnrolmentGrant {
    <#
      FORK 2 -- WHAT AN APPROVED KNOCK IS ANSWERED WITH: A POINTER, NEVER THE CONFIG.

      🔴 There is deliberately NO field here that could carry an admin, a role, or an assignment.
      The signed baseline bundle exists so a customer can verify what it received without trusting
      the transport; answering a knock with inline config would bypass exactly that guarantee and
      quietly create a second distribution channel with weaker properties than the first.
      So the grant says: *you are enrolled, at this ring -- now go and PULL the signed bundle from
      the channel you already verify.*

      🔒 It also does NOT carry a credential. The slave authenticates with its own identity, which
      is what MSP-3 established and what makes "the slave applies locally" true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Decision,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$BundleUri = '',
        [string]$KeyThumbprint = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not $Decision.enrolled) {
        return [ordered]@{
            kind = 'pim-enrolment-grant'; version = 1; tenantId = "$TenantId".Trim()
            enrolled = $false; ring = $null; bundleUri = ''; keyThumbprint = ''
            reason = "$($Decision.reason)"; decidedAtUtc = $NowUtc.ToString('o')
        }
    }
    return [ordered]@{
        kind = 'pim-enrolment-grant'; version = 1; tenantId = "$TenantId".Trim()
        enrolled = $true; ring = $Decision.ring
        # A POINTER to the signed artifact, plus the key to verify it with. Nothing else.
        bundleUri = "$BundleUri".Trim(); keyThumbprint = "$KeyThumbprint".Trim()
        reason = ''; decidedAtUtc = $NowUtc.ToString('o')
    }
}
