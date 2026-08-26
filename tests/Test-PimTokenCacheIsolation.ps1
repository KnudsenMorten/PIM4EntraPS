#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-22 -- a cached access token must never be handed to a DIFFERENT tenant.

    What happened: $script:PimTokenCache was keyed by the AUDIENCE alone --

        $key = $aud.ToLowerInvariant()

    -- with no tenant and no client id in the key. In any process that touches two
    tenants, the second one silently reused the first one's token, so every call meant
    for tenant B was made against tenant A. That is exactly the MSP master->slave fanout
    this product exists to run, and the failure mode is the worst kind: the calls
    SUCCEED, against the wrong directory.

    Proven live 2026-08-06 by the TEST-12 scenario matrix: an S6 (local-slave) run
    targeting a tenant that holds ZERO PIM groups reported "Groups live=85" -- the
    MASTER's group count -- and the verifier then found all six managed groups missing
    from the slave it was supposed to be managing. Read-only that pass; a write-shaped
    run would have applied a customer's desired state into the MSP's own tenant.

    The key is now audience + tenant + client id + credential KIND. These assertions are
    about ISOLATION, not caching: the cache is still expected to work (a repeat call for
    the same identity must not re-mint), because a fix that simply disabled caching would
    pass an isolation-only test and hammer the token endpoint.

    Offline. No network: the token acquisition functions are stubbed.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')

Write-Host "=== BUG-22: tokens are cached per IDENTITY, never shared across tenants ===" -ForegroundColor Cyan

# Stub the credential flow the engine actually uses in the MSP fanout (SPN + secret is the
# simplest to drive offline; the cert path shares the same cache key logic).
$script:Mints = 0
function Get-PimClientSecretToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret, [string]$Audience)
    $script:Mints++
    [pscustomobject]@{ token = "TOKEN[$TenantId/$ClientId]"; expiresUtc = (Get-Date).ToUniversalTime().AddHours(1) }
}

$MASTER = '9927fa1f-aaaa-bbbb-cccc-000000000001'
$SLAVE  = '4ff34194-aaaa-bbbb-cccc-000000000002'
$APP_M  = '7fe46852-1111-1111-1111-111111111111'
$APP_S  = '4e1e628c-2222-2222-2222-222222222222'

Clear-PimRestTokenCache
$script:Mints = 0

Write-Host "`n-- the MSP fanout: master then slave, same audience --" -ForegroundColor Yellow
$tM = Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x'
$tS = Get-PimRestToken -Resource graph -TenantId $SLAVE  -ClientId $APP_S -ClientSecret 'x'
Assert "master token is the master's"            ($tM -eq "TOKEN[$MASTER/$APP_M]")
Assert "SLAVE DOES NOT GET THE MASTER'S TOKEN"   ($tS -eq "TOKEN[$SLAVE/$APP_S]")
Assert "the two tokens differ"                   ($tM -ne $tS)
Assert "each identity minted its own"            ($script:Mints -eq 2)

Write-Host "`n-- ...and back to the master: still cached, not re-minted --" -ForegroundColor Yellow
$tM2 = Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x'
Assert "returning to the master reuses its token" ($tM2 -eq $tM)
Assert "no extra mint (the cache still caches)"   ($script:Mints -eq 2)

Write-Host "`n-- same tenant, DIFFERENT app --" -ForegroundColor Yellow
$tOther = Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_S -ClientSecret 'x'
Assert "a different client id gets its own token" ($tOther -eq "TOKEN[$MASTER/$APP_S]")
Assert "and that minted once more"                ($script:Mints -eq 3)

Write-Host "`n-- different audience, same identity --" -ForegroundColor Yellow
$arm = Get-PimRestToken -Resource arm -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x'
Assert "ARM does not receive the Graph token"     ($script:Mints -eq 4)

Write-Host "`n-- -Force always re-mints --" -ForegroundColor Yellow
$before = $script:Mints
[void](Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x' -Force)
Assert "-Force bypasses the cache"                ($script:Mints -eq ($before + 1))

Write-Host "`n-- an expired entry is not served --" -ForegroundColor Yellow
Clear-PimRestTokenCache
$script:Mints = 0
function Get-PimClientSecretToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret, [string]$Audience)
    $script:Mints++
    [pscustomobject]@{ token = "STALE[$TenantId]"; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds(30) }   # inside the 2-min skew window
}
[void](Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x')
[void](Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x')
Assert "a token expiring inside the skew window is re-minted" ($script:Mints -eq 2)

Write-Host "`n-- Clear-PimRestTokenCache empties everything --" -ForegroundColor Yellow
Clear-PimRestTokenCache
$script:Mints = 0
[void](Get-PimRestToken -Resource graph -TenantId $MASTER -ClientId $APP_M -ClientSecret 'x')
Assert "after a clear, the next call mints"       ($script:Mints -eq 1)

Write-Host "`n-- structural: the key carries the identity --" -ForegroundColor Yellow
$src = Get-Content (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') -Raw
$code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert "the cache key is not the bare audience"   (-not ($code -match '\$key\s*=\s*\$aud\.ToLowerInvariant\(\)\s*$'))
Assert "the key includes tenant and client"       ($code -match '\$key\s*=\s*\("\$aud\|\$tenant\|\$cid\|\$mode"\)')
Assert "identity is resolved BEFORE the lookup"   ($code.IndexOf('$tenant = Get-PimTenantId') -lt $code.IndexOf('$script:PimTokenCache.ContainsKey($key)'))

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
