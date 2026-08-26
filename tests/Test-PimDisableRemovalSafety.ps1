#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-13 (multi-domain / unmanaged admins) + BUG-14 (break-glass) -- which proposed
    removals on the account-disable path may actually proceed.

    Both were found by the operator asking why an admin- account was classed as a
    removal at all ("for example admin-mok-id@mortenknudsen.net").

    BUG-13: the desired UPN is {UserName}@{DefaultDomainUPN} -- ONE default domain --
    while a tenant legitimately holds admins across several verified domains. Measured
    live: 12 admin accounts over 3 suffixes; the 4 "removals" were EXACTLY the
    non-default-domain ones, including two Admin-PAW-* and the engine's own
    Admin-pimrest-ID.

    BUG-14: break-glass exclusion existed only in PIM-ApprovalGate (Manager revoke
    guard, approval-gated offboarding). The ENGINE's disable path -- the one that
    actually sets accountEnabled=$false, and the one that fired in the 2026-06-15
    incident -- had none. A break-glass account is BY DESIGN absent from definitions, so
    it lands in the removal set by default, and it is the account you reach for when
    everything else is locked out.

    Offline. No tenant, no network.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1'); . (Join-Path $shared 'PIM-DateSafe.ps1'); . (Join-Path $shared 'PIM-DisableGuard.ps1')

Write-Host "=== BUG-13 / BUG-14: what may actually be disabled ===" -ForegroundColor Cyan

Remove-Variable -Name PIM_BreakGlassAccounts,PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue
$env:PIM_BREAKGLASS_ACCOUNTS = ''

function L($upn) { [pscustomobject]@{ key = $upn; live = [pscustomobject]@{ userPrincipalName = $upn; id = "id-$upn" } } }
function D($upn) { [pscustomobject]@{ UserPrincipalName = $upn } }

# --- BUG-13: the local part is the identity; the domain is a tenant detail ------
Assert "local part of a UPN"            ((Get-PimUpnLocalPart -Upn 'Admin-MOK-ID@2linkit.net') -eq 'admin-mok-id')
Assert "  ...domain-independent"        ((Get-PimUpnLocalPart -Upn 'Admin-MOK-ID@mortenknudsen.net') -eq 'admin-mok-id')
Assert "  ...case-insensitive"          ((Get-PimUpnLocalPart -Upn 'ADMIN-MOK-ID@X') -eq 'admin-mok-id')
Assert "a bare name has no domain"      ((Get-PimUpnLocalPart -Upn 'Admin-MOK-ID') -eq 'admin-mok-id')
Assert "empty -> empty"                 ((Get-PimUpnLocalPart -Upn '') -eq '')

# THE case: the same admin, on a second verified domain, must NOT be a removal.
$desired = @(D 'Admin-MOK-ID@2linkit.net')
$r = Select-PimDisableRemovals -Remove @(L 'Admin-MOK-ID@mortenknudsen.net') -Desired $desired
Assert "the SAME admin on another domain is NOT removed" (@($r.remove).Count -eq 0)

# A genuinely undefined admin is UNMANAGED -- reported, not removed.
$r = Select-PimDisableRemovals -Remove @(L 'Admin-PAW-ID@mortenknudsen.net') -Desired $desired
Assert "an admin absent from desired IS removable (MSP deprovisioning)" (@($r.remove).Count -eq 1)
Assert "  ...it is reported as UNMANAGED"                       (@($r.unmanaged) -contains 'Admin-PAW-ID@mortenknudsen.net')
Assert "  ...and the reason names the removable count"          ("$($r.reason)" -match '1 kept')

# MSP MODEL (operator 2026-08-06): the desired set is AUTHORITATIVE. The same admin holds
# accounts across several tenants/domains; when they leave the MSP those accounts MUST be
# deprovisioned. So unmanaged stays removable by DEFAULT -- the brake is opt-OUT, and the
# real gates are disable-opt-in + breaker + G4 + break-glass.
$global:PIM_RemoveUnmanagedAdmins = $false
$r = Select-PimDisableRemovals -Remove @(L 'Admin-Rogue-ID@2linkit.net') -Desired $desired
Assert "the explicit report-only brake blocks removal" (@($r.remove).Count -eq 0)
Remove-Variable -Name PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue

$global:PIM_RemoveUnmanagedAdmins = $true
$r = Select-PimDisableRemovals -Remove @(L 'Admin-Rogue-ID@2linkit.net') -Desired $desired
Assert "with the brake OFF explicitly, an unmanaged admin IS removable" (@($r.remove).Count -eq 1)
Remove-Variable -Name PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue

# --- BUG-14: break-glass is never removable, opt-in or not ----------------------
$global:PIM_BreakGlassAccounts = 'break-glass@2linkit.net'
$desired2 = @(D 'Admin-A@x'; D 'break-glass@2linkit.net')
$r = Select-PimDisableRemovals -Remove @(L 'break-glass@2linkit.net') -Desired $desired2
Assert "a break-glass account is EXCLUDED"        (@($r.remove).Count -eq 0)
Assert "  ...and named in .breakGlass"            (@($r.breakGlass) -contains 'break-glass@2linkit.net')

# even with the unmanaged opt-in ON -- break-glass has NO override
$global:PIM_RemoveUnmanagedAdmins = $true
$r = Select-PimDisableRemovals -Remove @(L 'break-glass@2linkit.net') -Desired @()
Assert "break-glass survives even the unmanaged opt-in" (@($r.remove).Count -eq 0)
Remove-Variable -Name PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue

# break-glass by OBJECT ID as well as UPN
$global:PIM_BreakGlassAccounts = 'id-Admin-BG@x'
$r = Select-PimDisableRemovals -Remove @(L 'Admin-BG@x') -Desired @()
Assert "break-glass matched by object id too" (@($r.remove).Count -eq 0)
Remove-Variable -Name PIM_BreakGlassAccounts -Scope Global -EA SilentlyContinue

# --- the happy path must still work --------------------------------------------
$global:PIM_RemoveUnmanagedAdmins = $true
$r = Select-PimDisableRemovals -Remove @(L 'Admin-Old-ID@2linkit.net'; L 'Admin-MOK-ID@mortenknudsen.net') -Desired $desired
Assert "a defined admin on ANY domain is kept out of removals" (@($r.remove | ForEach-Object { $_.key }) -notcontains 'Admin-MOK-ID@mortenknudsen.net')
Assert "  ...while a genuinely rogue one proceeds (opt-in ON)"  (@($r.remove).Count -eq 1)
Remove-Variable -Name PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue

$r = Select-PimDisableRemovals -Remove @() -Desired $desired
Assert "an empty removal set is fine"        (@($r.remove).Count -eq 0)

# The case my first implementation got WRONG, kept as a regression guard: an account
# that IS attributable to a desired row must be excluded EVEN WITH the unmanaged opt-in
# on. Reaching the removal set at all means the diff keyed it wrong (BUG-13's shape), so
# it is excluded AND reported -- a key mismatch is a defect to fix, not to live with.
$global:PIM_RemoveUnmanagedAdmins = $true
$r = Select-PimDisableRemovals -Remove @(L 'Admin-MOK-ID@mortenknudsen.net') -Desired @(D 'Admin-MOK-ID@2linkit.net')
Assert "attributable account excluded EVEN with the opt-in ON" (@($r.remove).Count -eq 0)
Assert "  ...and reported as a key mismatch"                   (@($r.attributable) -contains 'Admin-MOK-ID@mortenknudsen.net')
Assert "  ...and NOT miscounted as unmanaged"                  (@($r.unmanaged).Count -eq 0)
Remove-Variable -Name PIM_RemoveUnmanagedAdmins -Scope Global -EA SilentlyContinue

# --- WIRING ---------------------------------------------------------------------
$core = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-EngineCore.ps1'))
Assert "the engine filters removals before the breaker" `
    ($core -match 'Select-PimDisableRemovals[\s\S]{0,2000}?Test-PimDisablePassAllowed')
Assert "  ...and REPORTS break-glass exclusions"  ($core -match 'BREAK-GLASS account\(s\) excluded')
Assert "  ...and REPORTS unmanaged admins"        ($core -match 'UNMANAGED admin account')
$prov = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-EngineProviders.ps1'))
Assert "ApplyRemove re-checks break-glass (defense in depth)" ($prov -match 'BREAK-GLASS account -- never disabled')
Assert "the Admins key is domain-independent"                 ($prov -match 'Get-PimUpnLocalPart')
# the engine must have its OWN break-glass definition -- ApprovalGate is not loaded there
$guard = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-DisableGuard.ps1'))
Assert "break-glass is available to the ENGINE, not just the Manager" ($guard -match 'function Get-PimBreakGlassIdentifiers')

Write-Host ""
Write-Host ("Disable removal safety (BUG-13/14): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
