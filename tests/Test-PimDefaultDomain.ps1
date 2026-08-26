#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-20 -- the target tenant's default verified domain must actually resolve, so a
    bare central UserName can become a real UPN in the MSP master->slave flow.

    What happened: Get-PimTargetDefaultDomain read

        $row = @($org) | Select-Object -First 1
        $def = @($row.verifiedDomains) | Where-Object { $_.isDefault }

    but Invoke-PimGraph (without -All) returns the RAW OData envelope --
    @odata.context + value -- so $row was the ENVELOPE, not the organization. The
    isDefault lookup found nothing and the function returned $null in EVERY tenant.

    Why that mattered: it exists for exactly one job -- Resolve-PimPrincipalId's
    documented fallback that turns a bare UserName into "{UserName}@{target default
    domain}" in the MSP fanout, because PIM-Assignments-Admins rows carry the bare
    central UserName. With the resolver always returning $null, that fallback had
    NEVER worked: every such assignment failed "unresolved principal/group".

    It hid because Admins.ApplyCreate carried its OWN copy of the same lookup, and that
    copy unwrapped .value correctly. So the engine CREATED the admin account at the
    right domain and then could not find the account it had just created. Measured live
    2026-08-06: the old shape saw 1 "verifiedDomain" and no default; the unwrapped shape
    saw 3 and the tenant's real default.

    The assertions that keep it fixed: the envelope shape resolves; a transient THROW is
    not cached as a permanent miss (with BUG-19 fixed the engine outlives one 429); and
    there is only ONE /organization lookup in the providers, so the two paths cannot
    silently disagree again.

    Offline. No tenant, no network: Invoke-PimGraph is stubbed.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-EngineCore.ps1')
. (Join-Path $shared 'PIM-EngineProviders.ps1')

Write-Host "=== BUG-20: the target default domain resolves from the real Graph shape ===" -ForegroundColor Cyan

# The REAL response shape: /organization returns an OData envelope whose .value holds
# one organization, which holds verifiedDomains. This is what the live probe returned.
$script:OrgResponse = [pscustomobject]@{
    '@odata.context' = 'https://graph.microsoft.com/v1.0/$metadata#organization'
    value = @(
        [pscustomobject]@{ verifiedDomains = @(
            [pscustomobject]@{ name = 'contoso.onmicrosoft.com'; isDefault = $false; isInitial = $true }
            [pscustomobject]@{ name = 'contoso.com';             isDefault = $true;  isInitial = $false }
            [pscustomobject]@{ name = 'mail.contoso.com';        isDefault = $false; isInitial = $false }
        )}
    )
}
$script:Calls = 0
$script:Throw = $false
function Invoke-PimGraph {
    param([string]$Method = 'GET', [string]$Path, [object]$Body, [switch]$All, [switch]$Beta, [hashtable]$Headers = @{})
    if ("$Path" -match '/organization') {
        $script:Calls++
        if ($script:Throw) { throw 'HTTP 429 : throttled' }
        return $script:OrgResponse
    }
    return @()
}

Write-Host "`n-- the real envelope shape --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
Assert "resolves the DEFAULT domain, not the initial one" ((Get-PimTargetDefaultDomain) -eq 'contoso.com')
Assert "it queried Graph exactly once"                    ($script:Calls -eq 1)
[void](Get-PimTargetDefaultDomain)
Assert "a resolved domain is cached (no second query)"    ($script:Calls -eq 1)

Write-Host "`n-- falls back to the INITIAL domain when none is default --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
$script:Calls = 0
$script:OrgResponse = [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @(
    [pscustomobject]@{ name = 'fabrikam.onmicrosoft.com'; isDefault = $false; isInitial = $true }
)}) }
Assert "uses isInitial when nothing is isDefault"         ((Get-PimTargetDefaultDomain) -eq 'fabrikam.onmicrosoft.com')

Write-Host "`n-- a bare object (no envelope) still works --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
$script:OrgResponse = [pscustomobject]@{ verifiedDomains = @([pscustomobject]@{ name = 'direct.com'; isDefault = $true }) }
Assert "an unwrapped organization object is handled too"  ((Get-PimTargetDefaultDomain) -eq 'direct.com')

Write-Host "`n-- a TRANSIENT failure is not a permanent miss --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
$script:Throw = $true; $script:Calls = 0
Assert "a throwing query returns null"                    ($null -eq (Get-PimTargetDefaultDomain))
$script:Throw = $false
$script:OrgResponse = [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @(
    [pscustomobject]@{ name = 'recovered.com'; isDefault = $true }
)}) }
Assert "the NEXT call retries and succeeds (429 != disabled)" ((Get-PimTargetDefaultDomain) -eq 'recovered.com')

Write-Host "`n-- a genuine no-domain answer IS cached --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
$script:OrgResponse = [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @() }) }
$script:Calls = 0
Assert "no domains -> null"                               ($null -eq (Get-PimTargetDefaultDomain))
[void](Get-PimTargetDefaultDomain)
Assert "and that miss is NOT re-queried"                  ($script:Calls -eq 1)

Write-Host "`n-- the bare-username fallback it exists for --" -ForegroundColor Yellow
Reset-PimTargetDefaultDomainCache
$script:OrgResponse = [pscustomobject]@{ value = @([pscustomobject]@{ verifiedDomains = @(
    [pscustomobject]@{ name = 'slave.example'; isDefault = $true }
)}) }
$Global:Users_All_ID = @([pscustomobject]@{ UserPrincipalName = 'Admin-PIMSCEN-MSPCloud-L1-T1-ID@slave.example'; Id = '11111111-2222-3333-4444-555555555555' })
$resolved = Resolve-PimPrincipalId 'Admin-PIMSCEN-MSPCloud-L1-T1-ID'
Assert "a BARE UserName resolves via the default domain"  ($resolved -eq '11111111-2222-3333-4444-555555555555')
$Global:Users_All_ID = @()

Write-Host "`n-- one resolver, so the paths cannot diverge again --" -ForegroundColor Yellow
$src = Get-Content (Join-Path $shared 'PIM-EngineProviders.ps1') -Raw
$code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$orgLookups = ([regex]::Matches($code, "Invoke-PimGraph -Path ""/organization")).Count
Assert "exactly ONE /organization lookup in the providers" ($orgLookups -eq 1)
Assert "Admins.ApplyCreate delegates to the resolver"      ($code -match '\$dom = "\$\(Get-PimTargetDefaultDomain\)"')

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
