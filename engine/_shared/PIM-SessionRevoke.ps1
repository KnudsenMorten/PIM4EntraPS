<#
  PIM-SessionRevoke.ps1 -- REQUIREMENTS §35.2

  PURE decision core for "revoke this admin's sign-in sessions" as a STANDALONE
  action (Graph: POST /users/{id}/revokeSignInSessions).

  WHY THIS FILE EXISTS
  --------------------
  The Graph call already existed, in exactly ONE place: inside the offboarding
  sequence (engine/_shared/PIM-Functions.psm1). That made the ONLY way to kill a
  compromised admin's live tokens "offboard them" -- so the proportionate
  response to a suspected token theft did not exist, and the operator's single
  option was the irreversible one. Availability of a proportionate action is
  itself a safety property (§35.2).

  WHAT THIS IS, AND IS NOT
  ------------------------
  This file makes NO calls and performs NO writes. It answers one question --
  "may this session revoke proceed?" -- and returns a verdict the caller acts on.
  That keeps it offline-testable and keeps the guard identical for every caller
  (Manager endpoint today, the §35.2 grid's bulk path later).

  THE SHAPE OF THE VERDICT
  ------------------------
  Revoking sessions is destructive-but-RECOVERABLE: the account survives, the
  user simply re-authenticates. So it deliberately does NOT carry offboarding's
  approval ceremony. What it does carry:

    1. the target must be an admin row THIS SOLUTION MANAGES -- same authority
       rule as the TAP reset endpoint. We do not offer an arbitrary-UPN weapon.
    2. break-glass / emergency accounts are REFUSED. Kicking the sessions of the
       account you would use to recover from the incident is the one case where
       this action makes things worse.
    3. it FAILS CLOSED. If the break-glass predicate is unavailable in this
       runtime we cannot prove the target is safe, so we refuse rather than
       assume. An unverifiable guard is not a passed guard.

  PS 5.1-safe (no ?./??, no ImportFromPem).
#>

# Shared fallbacks -- guarded so a host that already defines these (the Manager,
# PIM-ApprovalGate, PIM-DisableGuard) keeps ITS definition and we never shadow it
# with a second, subtly-different matcher.
if (-not (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue)) {
    function Get-PimBreakGlassIdentifiers {
        $raw = $global:PIM_BreakGlassAccounts
        if (-not $raw -and "$env:PIM_BREAKGLASS_ACCOUNTS") { $raw = "$env:PIM_BREAKGLASS_ACCOUNTS" }
        if (-not $raw) { return @() }
        $list = if ($raw -is [string]) { $raw -split '[;,]' } else { @($raw) }
        return @($list | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    }
}

function Get-PimSessionRevokeDecision {
    <#
      .SYNOPSIS
        Decide whether a sign-in-session revoke may proceed for one admin. Pure.

      .PARAMETER UserPrincipalName
        The revoke target.

      .PARAMETER AdminRows
        The managed admin set (Account-Definitions-Admins rows). The row is the
        AUTHORITY for whether this solution may act on the account at all --
        exactly as /api/admin-tap/reset treats it. Pass the rows in; this file
        does not read the store.

      .PARAMETER BreakGlassIdentifiers
        Optional. When omitted they are resolved via Get-PimBreakGlassIdentifiers.
        Pass an explicit (possibly empty) array to pin the value in a test.

      .OUTPUTS
        PSCustomObject: allowed(bool), code(string), reason(string), upn, row.
        code is one of: ok | no-upn | not-managed | break-glass | guard-unavailable
    #>
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [object[]]$AdminRows = @(),
        [string[]]$BreakGlassIdentifiers,
        [switch]$BreakGlassIdentifiersSpecified
    )

    $verdict = {
        param($ok, $code, $reason, $upn, $row)
        [pscustomobject]@{ allowed = [bool]$ok; code = "$code"; reason = "$reason"; upn = "$upn"; row = $row }
    }

    $upn = "$UserPrincipalName".Trim()
    if (-not $upn) {
        return (& $verdict $false 'no-upn' 'userPrincipalName is required' '' $null)
    }

    # 1. Is this an account we manage? Matching is case-insensitive because a UPN
    #    is case-insensitive in Entra, and a case-sensitive compare here would
    #    refuse a legitimate target for a reason no operator could guess.
    $row = $null
    foreach ($r in @($AdminRows)) {
        if (-not $r) { continue }
        $p = $r.PSObject.Properties['UserPrincipalName']
        if (-not $p) { continue }
        if ("$($p.Value)".Trim().ToLowerInvariant() -eq $upn.ToLowerInvariant()) { $row = $r; break }
    }
    if (-not $row) {
        return (& $verdict $false 'not-managed' `
            "'$upn' is not a managed admin row -- refusing to revoke sessions for an account this solution does not manage" `
            $upn $null)
    }

    # 2. Break-glass. FAIL CLOSED if we cannot evaluate it: an unverifiable guard
    #    is not a passed guard, and this is the exact account whose sessions must
    #    survive the incident you are responding to.
    if (-not (Get-Command Test-PimRowIsBreakGlass -ErrorAction SilentlyContinue)) {
        return (& $verdict $false 'guard-unavailable' `
            'cannot verify break-glass status in this runtime (Test-PimRowIsBreakGlass unavailable) -- refusing rather than assuming the target is safe' `
            $upn $row)
    }

    $bg = $null
    if ($BreakGlassIdentifiersSpecified -or $PSBoundParameters.ContainsKey('BreakGlassIdentifiers')) {
        $bg = @($BreakGlassIdentifiers)
    } else {
        $bg = @(Get-PimBreakGlassIdentifiers)
    }

    if (Test-PimRowIsBreakGlass -Row $row -Identifiers $bg) {
        return (& $verdict $false 'break-glass' `
            "'$upn' is a break-glass / emergency account -- refusing. Revoking the sessions of the account you would recover WITH is the one case where this action makes the incident worse." `
            $upn $row)
    }

    return (& $verdict $true 'ok' 'session revoke permitted' $upn $row)
}

function Get-PimSessionRevokeHttpStatus {
    <#
      Map a decision code to the HTTP status the Manager endpoint should return.
      Kept here, next to the codes, so the endpoint and the core cannot drift
      about what a given refusal MEANS.
    #>
    [CmdletBinding()]
    param([string]$Code)
    switch ("$Code") {
        'ok'                { return 200 }
        'no-upn'            { return 400 }
        'not-managed'       { return 404 }
        'break-glass'       { return 403 }
        'guard-unavailable' { return 503 }
        default             { return 500 }
    }
}
