#Requires -Version 5.1
<#
.SYNOPSIS
    Offline proof for STANDALONE sign-in-session revoke (REQUIREMENTS §35.2).
    Drives the PURE decision core (engine/_shared/PIM-SessionRevoke.ps1) over
    SEEDED admin rows -- no Graph, no SQL, and NO revoke is ever performed (this
    file computes verdicts only; it never calls revokeSignInSessions).

    Asserts:
      * an empty / whitespace UPN is refused (no-upn), not treated as "all";
      * an account NOT in the managed admin set is refused (not-managed) --
        the row is the authority, exactly as /api/admin-tap/reset treats it;
      * UPN matching is case-insensitive (a UPN is case-insensitive in Entra,
        and a case-sensitive compare would refuse for an unguessable reason);
      * a break-glass / emergency account is REFUSED (break-glass);
      * the guard FAILS CLOSED: with the break-glass predicate unavailable the
        verdict is a refusal (guard-unavailable), never an allow;
      * an ordinary managed admin is allowed (ok);
      * explicitly-passed break-glass identifiers win over the ambient ones,
        including an explicitly EMPTY list;
      * every code maps to the intended HTTP status, and the map has no gaps.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
$lib    = Join-Path $shared 'PIM-SessionRevoke.ps1'
$gate   = Join-Path $shared 'PIM-ApprovalGate.ps1'
T 'PIM-SessionRevoke.ps1 present' (Test-Path -LiteralPath $lib)
T 'PIM-ApprovalGate.ps1 present'  (Test-Path -LiteralPath $gate)
if (-not (Test-Path -LiteralPath $lib) -or -not (Test-Path -LiteralPath $gate)) {
    Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1
}

# Seeded managed admin set -- the shape Account-Definitions-Admins actually has.
$rows = @(
    [pscustomobject]@{ UserPrincipalName = 'Admin-JDO-ID@contoso.onmicrosoft.com'; DisplayName = 'J Doe';   ManagerEmail = 'm@contoso.com' }
    [pscustomobject]@{ UserPrincipalName = 'Admin-ASM-ID@contoso.onmicrosoft.com'; DisplayName = 'A Smith'; ManagerEmail = 'm@contoso.com' }
    [pscustomobject]@{ UserPrincipalName = 'BreakGlass-01@contoso.onmicrosoft.com'; DisplayName = 'Emergency'; ManagerEmail = '' }
)

# ============================================================================
# FAIL-CLOSED FIRST -- assert it BEFORE the break-glass predicate is loaded.
# This is the one ordering that matters in this file: once PIM-ApprovalGate is
# dot-sourced the predicate exists process-wide and this state is unreachable.
# ============================================================================
Write-Host "`n-- fails closed when the break-glass guard is unavailable --" -ForegroundColor Cyan
. $lib
$noGuard = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-JDO-ID@contoso.onmicrosoft.com' -AdminRows $rows
T 'no break-glass predicate -> REFUSED, not allowed' (-not $noGuard.allowed)
T 'no break-glass predicate -> code guard-unavailable' ($noGuard.code -eq 'guard-unavailable')
T 'the refusal says WHY it refused rather than assuming' ($noGuard.reason -match 'refusing rather than assuming')

# Now load the real predicate (pure; no writes) and continue.
. $gate
. $lib
T 'Test-PimRowIsBreakGlass is now available' ([bool](Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue))

# === input validation =======================================================
Write-Host "`n-- input validation --" -ForegroundColor Cyan
$empty = Get-PimSessionRevokeDecision -UserPrincipalName '' -AdminRows $rows -BreakGlassIdentifiers @()
T 'empty UPN -> refused'                 (-not $empty.allowed)
T 'empty UPN -> code no-upn'             ($empty.code -eq 'no-upn')
$ws = Get-PimSessionRevokeDecision -UserPrincipalName "   `t " -AdminRows $rows -BreakGlassIdentifiers @()
T 'whitespace-only UPN -> refused'       (-not $ws.allowed)
T 'whitespace-only UPN -> code no-upn'   ($ws.code -eq 'no-upn')
$nullUpn = Get-PimSessionRevokeDecision -UserPrincipalName $null -AdminRows $rows -BreakGlassIdentifiers @()
T 'null UPN -> refused (never "all")'    (-not $nullUpn.allowed)

# === the row is the authority ===============================================
Write-Host "`n-- the managed-admin row is the authority --" -ForegroundColor Cyan
$unmanaged = Get-PimSessionRevokeDecision -UserPrincipalName 'random.person@contoso.com' -AdminRows $rows -BreakGlassIdentifiers @()
T 'unmanaged account -> refused'         (-not $unmanaged.allowed)
T 'unmanaged account -> code not-managed' ($unmanaged.code -eq 'not-managed')
T 'the refusal names the account'        ($unmanaged.reason -match [regex]::Escape('random.person@contoso.com'))
$noRows = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-JDO-ID@contoso.onmicrosoft.com' -AdminRows @() -BreakGlassIdentifiers @()
T 'empty admin set -> refused (not an implicit allow)' (-not $noRows.allowed)
T 'empty admin set -> code not-managed'  ($noRows.code -eq 'not-managed')

Write-Host "`n-- UPN matching is case-insensitive --" -ForegroundColor Cyan
$upper = Get-PimSessionRevokeDecision -UserPrincipalName 'ADMIN-JDO-ID@CONTOSO.ONMICROSOFT.COM' -AdminRows $rows -BreakGlassIdentifiers @()
T 'upper-cased UPN still resolves the row' ($upper.allowed)
$padded = Get-PimSessionRevokeDecision -UserPrincipalName '  Admin-JDO-ID@contoso.onmicrosoft.com  ' -AdminRows $rows -BreakGlassIdentifiers @()
T 'surrounding whitespace is trimmed'      ($padded.allowed)

# === break-glass ============================================================
Write-Host "`n-- break-glass is refused --" -ForegroundColor Cyan
$bgIds = @('breakglass-01@contoso.onmicrosoft.com')
$bg = Get-PimSessionRevokeDecision -UserPrincipalName 'BreakGlass-01@contoso.onmicrosoft.com' -AdminRows $rows -BreakGlassIdentifiers $bgIds
T 'break-glass account -> refused'       (-not $bg.allowed)
T 'break-glass account -> code break-glass' ($bg.code -eq 'break-glass')
T 'the refusal explains the incident logic' ($bg.reason -match 'recover WITH')
$other = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-ASM-ID@contoso.onmicrosoft.com' -AdminRows $rows -BreakGlassIdentifiers $bgIds
T 'a NON-break-glass admin is unaffected by the list' ($other.allowed)

Write-Host "`n-- explicit identifiers beat the ambient ones --" -ForegroundColor Cyan
$global:PIM_BreakGlassAccounts = 'Admin-JDO-ID@contoso.onmicrosoft.com'
try {
    $ambient = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-JDO-ID@contoso.onmicrosoft.com' -AdminRows $rows
    T 'ambient $PIM_BreakGlassAccounts is honoured when none passed' (-not $ambient.allowed -and $ambient.code -eq 'break-glass')
    $overridden = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-JDO-ID@contoso.onmicrosoft.com' -AdminRows $rows -BreakGlassIdentifiers @()
    T 'an explicitly EMPTY list overrides the ambient value' ($overridden.allowed)
} finally { Remove-Variable -Name PIM_BreakGlassAccounts -Scope Global -ErrorAction SilentlyContinue }

# === the happy path =========================================================
Write-Host "`n-- an ordinary managed admin is allowed --" -ForegroundColor Cyan
$ok = Get-PimSessionRevokeDecision -UserPrincipalName 'Admin-JDO-ID@contoso.onmicrosoft.com' -AdminRows $rows -BreakGlassIdentifiers @()
T 'ordinary managed admin -> allowed'    ($ok.allowed)
T 'ordinary managed admin -> code ok'    ($ok.code -eq 'ok')
T 'the verdict carries the resolved row' ($null -ne $ok.row -and $ok.row.DisplayName -eq 'J Doe')
T 'the verdict echoes the trimmed upn'   ($ok.upn -eq 'Admin-JDO-ID@contoso.onmicrosoft.com')

# === status mapping =========================================================
Write-Host "`n-- code -> HTTP status --" -ForegroundColor Cyan
T 'ok -> 200'                ((Get-PimSessionRevokeHttpStatus -Code 'ok') -eq 200)
T 'no-upn -> 400'            ((Get-PimSessionRevokeHttpStatus -Code 'no-upn') -eq 400)
T 'break-glass -> 403'       ((Get-PimSessionRevokeHttpStatus -Code 'break-glass') -eq 403)
T 'not-managed -> 404'       ((Get-PimSessionRevokeHttpStatus -Code 'not-managed') -eq 404)
T 'guard-unavailable -> 503' ((Get-PimSessionRevokeHttpStatus -Code 'guard-unavailable') -eq 503)
T 'an unknown code -> 500 (never a 2xx)' ((Get-PimSessionRevokeHttpStatus -Code 'something-new') -eq 500)

# Every code the core can emit must have a non-500 mapping -- otherwise a new
# refusal reason would silently surface to the caller as an internal error.
$emitted = @('ok','no-upn','not-managed','break-glass','guard-unavailable')
$unmapped = @($emitted | Where-Object { (Get-PimSessionRevokeHttpStatus -Code $_) -eq 500 })
T 'every emitted code has an explicit status' ($unmapped.Count -eq 0)

# The core must never perform the revoke itself.
$src = Get-Content -LiteralPath $lib -Raw
T 'the core makes no Graph call'          ($src -notmatch 'Invoke-PimGraph|Invoke-MgGraphRequest|Invoke-RestMethod')
T 'the core never names revokeSignInSessions as a call it makes' ($src -notmatch '(?m)^\s*[^#]*Invoke.*revokeSignInSessions')

# === §35.3 level scoping: Test-PimPortalCanManageAdmin ======================
Write-Host "`n-- §35.3: the caller must be permitted to act on THIS admin --" -ForegroundColor Cyan
$portalLib = Join-Path $shared 'PIM-PortalAccess.ps1'
if (Test-Path -LiteralPath $portalLib) {
    . $portalLib
    T 'Test-PimPortalCanManageAdmin exists' ([bool](Get-Command Test-PimPortalCanManageAdmin -ErrorAction SilentlyContinue))

    $mk = { param($caps, $managed) [pscustomobject]@{ capabilities = $caps; managedAdmins = $managed } }
    $target = 'Admin-JDO-ID@contoso.onmicrosoft.com'

    # DEFAULT-DENY is the headline. manage-account is a NEW capability, so no existing
    # profile holds it -- and that must refuse, not fall back to something permissive.
    T 'a null profile is REFUSED'                     (-not (Test-PimPortalCanManageAdmin -Profile $null -AdminName $target))
    T 'a profile with NO capabilities is REFUSED'     (-not (Test-PimPortalCanManageAdmin -Profile (& $mk @() @('*')) -AdminName $target))
    # The whole point of the separate capability: granting access must not imply destroying it.
    T 'assign-admin alone does NOT grant it'          (-not (Test-PimPortalCanManageAdmin -Profile (& $mk @('assign-admin','assign') @('*')) -AdminName $target))
    T 'enable-consultants alone does NOT grant it'    (-not (Test-PimPortalCanManageAdmin -Profile (& $mk @('enable-consultants') @('*')) -AdminName $target))
    T 'manage-account + managedAdmins * is ALLOWED'   (Test-PimPortalCanManageAdmin -Profile (& $mk @('manage-account') @('*')) -AdminName $target)
    T 'manage-account but NOT this admin is REFUSED'  (-not (Test-PimPortalCanManageAdmin -Profile (& $mk @('manage-account') @('someone.else@x.io')) -AdminName $target))
    T 'manage-account naming this admin is ALLOWED'   (Test-PimPortalCanManageAdmin -Profile (& $mk @('manage-account') @($target)) -AdminName $target)
    T 'the managedAdmins match is case-insensitive'   (Test-PimPortalCanManageAdmin -Profile (& $mk @('manage-account') @($target.ToUpperInvariant())) -AdminName $target)
    T 'the capability match is case-insensitive'      (Test-PimPortalCanManageAdmin -Profile (& $mk @('MANAGE-ACCOUNT') @('*')) -AdminName $target)
    T 'SuperAdmin bypasses, profile or not'           (Test-PimPortalCanManageAdmin -Profile $null -AdminName $target -IsSuperAdmin)

    # --- operator 2026-08-31: "grant manage-account (level 0-2)" -------------
    # The capability shipped default-deny, which left the §35.2 grid empty for everyone but
    # SuperAdmin. L0-L2 profiles -- the admin/helpdesk tiers that already manage privileged
    # accounts daily -- now hold it implicitly.
    $mkL = { param($lvl, $caps, $managed) [pscustomobject]@{ levelMax = $lvl; capabilities = $caps; managedAdmins = $managed } }
    T 'levelMax 0 grants manage-account implicitly' (Test-PimPortalCanManageAdmin -Profile (& $mkL 0 @() @('*')) -AdminName $target)
    T 'levelMax 1 grants it'                        (Test-PimPortalCanManageAdmin -Profile (& $mkL 1 @() @('*')) -AdminName $target)
    T 'levelMax 2 grants it'                        (Test-PimPortalCanManageAdmin -Profile (& $mkL 2 @() @('*')) -AdminName $target)
    # L3+ is the business/workload-owner tier -- still explicit-only, so the relaxation is
    # scoped by level rather than being a default drifting open.
    T 'levelMax 3 does NOT grant it implicitly'     (-not (Test-PimPortalCanManageAdmin -Profile (& $mkL 3 @() @('*')) -AdminName $target))
    T 'levelMax 3 WITH the capability is allowed'   (Test-PimPortalCanManageAdmin -Profile (& $mkL 3 @('manage-account') @('*')) -AdminName $target)
    T 'a missing levelMax is not treated as 0'      (-not (Test-PimPortalCanManageAdmin -Profile (& $mkL $null @() @('*')) -AdminName $target))
    T 'a non-numeric levelMax is not treated as 0'  (-not (Test-PimPortalCanManageAdmin -Profile (& $mkL 'high' @() @('*')) -AdminName $target))
    # 🔒 The level grant does NOT widen WHICH admins are reachable -- managedAdmins still decides.
    T 'level 0-2 still respects managedAdmins'      (-not (Test-PimPortalCanManageAdmin -Profile (& $mkL 0 @() @('someone.else@x.io')) -AdminName $target))
    T '   ...and allows a named one'                (Test-PimPortalCanManageAdmin -Profile (& $mkL 2 @() @($target)) -AdminName $target)

    # Wiring: the revoke endpoint must actually consult it, and BEFORE the revoke guard --
    # otherwise a 404-vs-403 difference tells an out-of-scope caller whether the target is a
    # managed row, which is an enumeration oracle.
    $srvP = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager\Open-PimManager.ps1'
    if (Test-Path -LiteralPath $srvP) {
        $s = (Get-Content -LiteralPath $srvP -Raw) -replace '(?m)^\s*#.*$', ''
        T 'the revoke endpoint consults the predicate' ($s -match 'Test-PimPortalCanManageAdmin')
        $iScope  = $s.IndexOf('Test-PimPortalCanManageAdmin')
        $iGuard  = $s.IndexOf('Get-PimSessionRevokeDecision')
        T 'scope check runs BEFORE the revoke guard'   ($iScope -gt 0 -and $iGuard -gt 0 -and $iScope -lt $iGuard)
    } else { T 'Open-PimManager.ps1 present for wiring asserts' $false }
} else { T 'PIM-PortalAccess.ps1 present' $false }

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
