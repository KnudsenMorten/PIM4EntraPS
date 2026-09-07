#Requires -Version 5.1
<#
.SYNOPSIS
    MSP-5 -- the slave-enrolment handshake ("the slave knocks on the door"). OFFLINE, pure.

    The operator's shape: a slave is deployed with minimum config, KNOCKS on the master, and the
    master answers with the config it is allowed to have. The mechanism was never the hard part --
    the RETURN PATH is, because framework §8's uplink is append-only by design and "the slave
    receives its allowed config" adds a read surface with a different risk profile.

    So most of these assertions are about what the handshake REFUSES to do:
      * knocking is not joining          -- enrolment needs an explicit MSP-side approval
      * an approved knock returns a POINTER, never config -- or it becomes a second distribution
        channel with weaker guarantees than the signed bundle it would replace
      * the master ANSWERS; it never reaches into the customer
      * the ring is the operator's to assign, never the requester's to choose

    No network, no store, no tenant.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-Downlink.ps1')   # Get-PimDownlinkValue
. (Join-Path $root 'engine\_shared\PIM-Enrolment.ps1')

Write-Host "=== MSP-5: the slave-enrolment handshake (offline) ===" -ForegroundColor Cyan
Write-Host ("  (PowerShell {0})" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray

$tid = '11111111-2222-3333-4444-555555555555'
$req = New-PimEnrolmentRequest -TenantId $tid -DisplayName 'Contoso Ltd' -RequestedRing 0 `
        -Scenario 'S6' -UplinkUri 'https://uplink.example/api' -AdminAccountPrefixes @('Admin-')

# ===========================================================================
Write-Host "`n== THE KNOCK: a claim of identity, not proof of one ==" -ForegroundColor Cyan
# ===========================================================================
T 'the request is a self-describing document' ("$($req.kind)" -eq 'pim-enrolment-request' -and $req.version -ge 1)
T '  ...naming the tenant and a HUMAN-readable name' ($req.tenantId -eq $tid -and $req.displayName -eq 'Contoso Ltd')
T '  ...and carrying a nonce, so a replay can be told from a retry' ("$($req.nonce)".Trim().Length -gt 0)
# 🔒 A knock carries NO CREDENTIAL. The proof of identity is the authenticated channel it arrives
# on (framework §8.2); a secret in the body would make the document itself worth stealing.
$reqJson = ($req | ConvertTo-Json -Depth 6)
T '  ...and NO credential/secret anywhere in it' (
    $reqJson -notmatch '(?i)"(secret|password|clientSecret|thumbprint|token|key)"\s*:')
# FORK 4: the JSON is the source of truth, so it has to survive the wire.
T '  ...and it round-trips through JSON (the document IS the interface)' (
    ((($req | ConvertTo-Json -Depth 6) | ConvertFrom-Json).tenantId) -eq $tid)
# IMP-13: the slave declares its own naming conventions at the moment the mismatch is cheapest to
# fix -- before a single account has been created in it.
T '  ...and it declares the slave''s OWN admin naming prefixes (IMP-13, fixed at the cheapest moment)' (
    @($req.adminAccountPrefixes) -contains 'Admin-')

# --- shape validation fails CLOSED ------------------------------------------------------------
T 'a well-formed request validates' ((Test-PimEnrolmentRequest -Request $req).ok)
T '  ...a null document does not' (-not (Test-PimEnrolmentRequest -Request $null).ok)
T '  ...nor a document of the wrong KIND (an uplink record is not an enrolment)' (
    -not (Test-PimEnrolmentRequest -Request ([ordered]@{ kind = 'pim-acceptance-record' })).ok)
$noTid = New-PimEnrolmentRequest -TenantId 'not-a-guid' -DisplayName 'X'
T '  ...nor a tenantId that is not a GUID' (-not (Test-PimEnrolmentRequest -Request $noTid).ok)
# 🪤 Built as a raw document, NOT through New-PimEnrolmentRequest, and that is the honest fixture:
# the builder's [Parameter(Mandatory)] rejects an empty DisplayName before the validator ever runs,
# so testing through it would have proved the BINDER works, not the validator. A request arriving
# over the wire never went through the builder -- which is precisely why the validator exists.
$noName = [ordered]@{ kind = 'pim-enrolment-request'; version = 1; tenantId = $tid; displayName = ''; nonce = 'n1' }
T '  ...nor a request with no display name (an operator would be approving an ID)' (
    -not (Test-PimEnrolmentRequest -Request $noName).ok)
$noNonce = [ordered]@{ kind = 'pim-enrolment-request'; version = 1; tenantId = $tid; displayName = 'X'; nonce = '' }
T '  ...nor one with no nonce (a replay would be indistinguishable from a retry)' (
    -not (Test-PimEnrolmentRequest -Request $noNonce).ok)

# ===========================================================================
Write-Host "`n== FORK 1: KNOCKING IS NOT JOINING ==" -ForegroundColor Cyan
# ===========================================================================
# 🔴 Without an approval gate, any tenant holding a valid token joins the fleet and starts
# receiving the MSP's central admin accounts -- privileged identities. Default is REFUSE.
$dNone = Get-PimEnrolmentDecision -Request $req -Registry @()
T 'an UNAPPROVED tenant is REFUSED (default is refuse, not admit)' (-not $dNone.enrolled)
# 🔑 "Never heard of you" and "we said no" are different facts, and an operator reading a log
# needs to tell them apart -- an unknown tenant must never be the easy case.
T '  ...reported as UNKNOWN, distinctly from a denial' ("$($dNone.state)" -eq 'unknown')
T '  ...with a reason that says knocking is not joining' ($dNone.reason -match 'knocking is not joining')
$dDenied = Get-PimEnrolmentDecision -Request $req -Registry @(@{ tenantId = $tid; state = 'denied' })
T 'an explicitly DENIED tenant is refused, and says denied' (-not $dDenied.enrolled -and "$($dDenied.state)" -eq 'denied')
$dOk = Get-PimEnrolmentDecision -Request $req -Registry @(@{ tenantId = $tid; state = 'approved'; ring = 3 })
T 'an APPROVED tenant enrols' ($dOk.enrolled -and "$($dOk.state)" -eq 'approved')
# 🪤 THE CONTROL. Without an approval that actually works, every refusal above passes for the most
# boring possible reason -- the "test whose premise is false" trap this project keeps paying for.
T '  ...which is the CONTROL: the refusals above are not just a broken function' ($dOk.enrolled -eq $true)
T '  ...and a malformed request is refused before any registry lookup happens' (
    "$((Get-PimEnrolmentDecision -Request ([ordered]@{ kind = 'nonsense' }) -Registry @(@{ tenantId = $tid; state = 'approved'; ring = 0 })).state)" -eq 'malformed')

# --- the ring is the OPERATOR's ---------------------------------------------------------------
# 🔒 A tenant that could choose its own ring could choose ring 0 -- the earliest, least-proven
# baseline -- which is the exact inverse of what rings exist to do.
T 'FORK 1: the granted ring comes from the REGISTRY, not from the request' (
    $req.requestedRing -eq 0 -and $dOk.ring -eq 3)
$dNoRing = Get-PimEnrolmentDecision -Request $req -Registry @(@{ tenantId = $tid; state = 'approved' })
T '  ...and an approval with NO ring is refused rather than defaulted' (
    -not $dNoRing.enrolled -and $dNoRing.reason -match 'no ring was assigned')

# ===========================================================================
Write-Host "`n== FORK 2: THE ANSWER IS A POINTER, NEVER THE CONFIG ==" -ForegroundColor Cyan
# ===========================================================================
# 🔴 The signed baseline bundle exists so a customer can verify what it received WITHOUT trusting
# the transport. Answering a knock with inline config bypasses that guarantee and creates a second
# distribution channel with weaker properties than the one it replaces.
$grant = New-PimEnrolmentGrant -Decision $dOk -TenantId $tid -BundleUri 'https://blob.example/baseline.json' -KeyThumbprint 'ABC123'
T 'an approved grant says enrolled, at the operator''s ring' ($grant.enrolled -and $grant.ring -eq 3)
T '  ...and points at the SIGNED bundle plus the key to verify it' (
    "$($grant.bundleUri)" -eq 'https://blob.example/baseline.json' -and "$($grant.keyThumbprint)" -eq 'ABC123')
# 🔒 THE ASSERTION THAT MATTERS: no field could carry an artifact even if somebody wanted it to.
$grantJson = ($grant | ConvertTo-Json -Depth 6)
T '  ...and carries NO admins, roles, assignments or definitions -- not even empty ones' (
    $grantJson -notmatch '(?i)"(admins|roles|assignments|definitions|groups|policy)"\s*:')
T '  ...nor any credential for the slave to use (it applies with its OWN identity, MSP-3)' (
    $grantJson -notmatch '(?i)"(secret|password|clientSecret|token)"\s*:')
$refusedGrant = New-PimEnrolmentGrant -Decision $dNone -TenantId $tid -BundleUri 'https://blob.example/baseline.json' -KeyThumbprint 'ABC123'
# 🪤 A REFUSAL MUST NOT LEAK THE POINTER. Handing an unenrolled tenant the bundle URI would make
# the approval gate decorative -- the artifact is the thing being protected.
T 'a REFUSED grant carries no bundle pointer at all' (
    -not $refusedGrant.enrolled -and "$($refusedGrant.bundleUri)" -eq '' -and "$($refusedGrant.keyThumbprint)" -eq '')
T '  ...and still explains itself (a refusal nobody can act on gets worked around)' (
    "$($refusedGrant.reason)".Trim().Length -gt 0)
T '  ...and is stamped with WHEN it was decided (silence and refusal must be distinguishable)' (
    "$($refusedGrant.decidedAtUtc)".Trim().Length -gt 0)

# ===========================================================================
Write-Host "`n== FORK 3: THE MASTER ANSWERS; IT NEVER REACHES IN ==" -ForegroundColor Cyan
# ===========================================================================
$src = Get-Content -LiteralPath (Join-Path $root 'engine\_shared\PIM-Enrolment.ps1') -Raw
$code = (($src -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
# 🪤 Comment-stripped, because this file ARGUES about connections at length and a source assert
# that reads prose would be satisfied by its own documentation.
T 'the enrolment core opens NO connection to a managed tenant' (
    $code -notmatch '(?i)(Invoke-RestMethod|Invoke-WebRequest|New-PimSqlConnection|Connect-Az|Connect-Mg)')
T '  ...and performs no writes of any kind' (
    $code -notmatch '(?i)(Set-PimSqlRow|Remove-PimSqlRow|Invoke-PimSqlNonQuery|-Method\s+(POST|PUT|PATCH|DELETE))')
# ◻ And the transport is deliberately absent -- framework §8.2 owns it, exactly as MSP-3 step 5
# left the uplink pipe to PlatformMonitoring. Asserted so the absence reads as a decision.
T 'FORK: PIM does NOT invent a transport (framework §8.2 owns it)' (
    $src -match '§8\.2' -and $code -notmatch '(?i)HttpListener')

Write-Host ""
Write-Host ("==== enrolment test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
