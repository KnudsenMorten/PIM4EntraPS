#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-15 -- the Admins scope's ApplyCreate must POST a REAL userPrincipalName.

    What happened: the BUG-13 fix (correctly) changed the provider's KeyOf from the
    whole UPN to the UPN LOCAL PART -- an admin's identity is the account name, the
    domain is a tenant detail. ApplyCreate was left reading `$item.key` as if it were
    still a UPN, so the engine started POSTing `userPrincipalName = "admin-xxx-id"`
    with NO DOMAIN and Entra rejected every new admin account with HTTP 400
    "The domain portion of the userPrincipalName property is invalid."

    Nothing offline caught it: the suite was 595/0 green while the shipped, DEPLOYED
    engine could not create a single admin account. The diff and the guards were
    tested; the CREATE BODY never was. -WhatIf plans do not call ApplyCreate at all.

    So this file tests the one thing that was missing: what the provider actually
    SENDS. It drives Admins.ApplyCreate with a stubbed Graph and inspects the POST
    body. The key-shape assertion is the durable one -- it fails again the moment the
    diff key and the create body diverge, whichever of the two moves.

    Offline. No tenant, no network -- Invoke-PimGraph is stubbed and records calls.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-DisableGuard.ps1')
. (Join-Path $shared 'PIM-EngineProviders.ps1')

Write-Host "=== BUG-15: the Admins create posts a real UPN ===" -ForegroundColor Cyan

# ---- Graph stub -------------------------------------------------------------
# Defined AFTER the providers are loaded, so the provider scriptblocks resolve to it
# at call time. Records every call; answers the default-domain lookup.
$script:GraphCalls = New-Object System.Collections.Generic.List[object]
function Invoke-PimGraph {
    param([string]$Method = 'GET', [string]$Path, [object]$Body, [hashtable]$Headers, [switch]$All)
    $script:GraphCalls.Add([pscustomobject]@{ method = $Method; path = $Path; body = $Body })
    if ($Path -like '/organization*') {
        return [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @(
            [pscustomobject]@{ name = 'contoso.onmicrosoft.com'; isDefault = $true }
            [pscustomobject]@{ name = 'other.example';           isDefault = $false }) }) }
    }
    return [pscustomobject]@{ id = 'new-user-id'; userPrincipalName = $Body.userPrincipalName }
}
function Get-LastCreateBody {
    $c = @($script:GraphCalls | Where-Object { $_.method -eq 'POST' -and $_.path -eq '/users' }) | Select-Object -Last 1
    if ($c) { return $c.body }
    return $null
}

$provider = New-PimAdminsProvider
Assert "the Admins provider is the account-disable provider" ([bool]$provider.isAccountDisable)

# ---- the shape the engine really passes -------------------------------------
# $item.key is whatever KeyOf produced. Build it the same way the orchestrator does,
# so this test tracks KeyOf instead of hardcoding an assumption about it.
function New-CreateItem($row) {
    $key = & $provider.KeyOf $row
    return [pscustomobject]@{ key = $key; desired = $row }
}

$row = [pscustomobject]@{
    UserName = 'Admin-TEST-OPS-ID'; DisplayName = 'Test Ops Admin'
    UserPrincipalName = 'Admin-TEST-OPS-ID@contoso.onmicrosoft.com'
    UserType = 'Member'; AccountStatus = 'Enabled'
}
$item = New-CreateItem $row

# The regression itself: the key is NOT an address any more.
Assert "KeyOf returns the UPN local part (BUG-13), not a UPN" ("$($item.key)" -notmatch '@')

$script:GraphCalls.Clear()
& $provider.ApplyCreate $item @{} | Out-Null
$body = Get-LastCreateBody
Assert "a POST /users was issued"                       ($null -ne $body)
Assert "userPrincipalName contains a domain"            ("$($body.userPrincipalName)" -match '@')
Assert "  ...and is EXACTLY the desired row's UPN"      ("$($body.userPrincipalName)" -eq 'Admin-TEST-OPS-ID@contoso.onmicrosoft.com')
Assert "mailNickname is the local part (no '@')"        ("$($body.mailNickname)" -eq 'Admin-TEST-OPS-ID')
Assert "displayName comes from the row"                 ("$($body.displayName)" -eq 'Test Ops Admin')
Assert "the account is created ENABLED"                 ([bool]$body.accountEnabled)
Assert "a password profile is set (never a blank pw)"   ("$($body.passwordProfile.password)".Length -ge 12)

# THE durable assertion: the create body must never be the diff key.
Assert "the create body is NOT the diff key"            ("$($body.userPrincipalName)" -ne "$($item.key)")

# ---- fallback: a row with no UPN composes one from the default domain --------
$rowNoUpn = [pscustomobject]@{ UserName = 'Admin-TEST-NOUPN-ID'; DisplayName = 'No UPN Admin' }
$item2 = New-CreateItem $rowNoUpn
$script:GraphCalls.Clear()
& $provider.ApplyCreate $item2 @{} | Out-Null
$body2 = Get-LastCreateBody
Assert "no UPN on the row -> composed from the default verified domain" ("$($body2.userPrincipalName)" -eq 'admin-test-noupn-id@contoso.onmicrosoft.com')
Assert "  ...and it resolved the DEFAULT domain, not just any" ("$($body2.userPrincipalName)" -notmatch 'other\.example')

# ---- fail-closed: no UPN and no resolvable domain -> refuse ------------------
# A domainless POST is a guaranteed 400; guessing a domain would be worse. The only
# safe outcome is to refuse loudly.
function Invoke-PimGraph {
    param([string]$Method = 'GET', [string]$Path, [object]$Body, [hashtable]$Headers, [switch]$All)
    if ($Path -like '/organization*') { throw 'no organization read in this context' }
    $script:GraphCalls.Add([pscustomobject]@{ method = $Method; path = $Path; body = $Body })
    return [pscustomobject]@{ id = 'x' }
}
# BUG-20: ApplyCreate no longer carries its own copy of the /organization lookup -- it
# delegates to Get-PimTargetDefaultDomain, which CACHES a resolved domain per process.
# The previous case above resolved contoso.onmicrosoft.com for this same tenant, so
# without dropping that cache this case would be handed the cached domain and never reach
# the fail-closed branch it exists to prove. Clearing it is what makes "no resolvable
# domain" actually true here, rather than a fact the stub asserts and the code never sees.
Reset-PimTargetDefaultDomainCache
$script:GraphCalls.Clear()
$threw = $false; $msg = ''
try { & $provider.ApplyCreate (New-CreateItem $rowNoUpn) @{} | Out-Null } catch { $threw = $true; $msg = "$($_.Exception.Message)" }
Assert "no UPN + no resolvable domain -> THROWS (fail closed)" $threw
Assert "  ...and says why, naming the account"                 ($msg -match 'domainless|UserPrincipalName' -and $msg -match 'admin-test-noupn-id')
Assert "  ...and posted NOTHING"                               (@($script:GraphCalls | Where-Object { $_.method -eq 'POST' }).Count -eq 0)

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
