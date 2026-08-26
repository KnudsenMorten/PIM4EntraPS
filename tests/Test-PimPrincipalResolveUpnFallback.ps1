#Requires -Version 5.1
<#
.SYNOPSIS
    Resolve-PimPrincipalId UPN-fallback (MSP master->slave) -- OFFLINE, in-proc, with a
    STUBBED Graph layer. Proves the bare-UserName -> UserName@<defaultDomain> fallback that
    makes the admin->role-group eligibility assignment land in the slave tenant.

.DESCRIPTION
    Background: in the MSP S5/S6 master->slave flow the fanout rewrites UserName->UPN when
    CREATING the slave admin account, but the desired PIM-Assignments-Admins rows still carry
    the BARE central UserName (e.g. PIMSCEN-Admin-MSPCloud-L1-T1-ID). Resolve-PimPrincipalId
    only looked up /users/{value} as a UPN, so the bare value 404'd -> "AdminMembers: unresolved
    principal/group" and the admin never became eligible on the group.

    The fix adds a contained fallback: a value WITHOUT '@' that fails the direct lookup is
    retried once as "{UserName}@{targetTenantDefaultDomain}"; the default domain is fetched
    ONCE from Graph (/organization verifiedDomains where isDefault) and cached per run.

    This test dot-sources engine/_shared/PIM-EngineProviders.ps1 with Invoke-PimGraph (and
    Add-PimContextObject) STUBBED -- no live tenant, no modules. It asserts:
      (1) a real UPN (x@dom) resolves DIRECTLY, unchanged (no fallback, no domain query);
      (2) a bare UserName that 404s on the direct lookup resolves via UserName@<defaultDomain>;
      (3) a bare UserName that resolves nowhere returns $null (no crash, no wrong match);
      (4) the default domain is fetched ONCE and cached (one /organization call, even across
          many fallback resolutions).

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root  = Split-Path -Parent $PSScriptRoot                 # ...\PIM4EntraPS
$provPath = Join-Path $root 'engine\_shared\PIM-EngineProviders.ps1'
T 'PIM-EngineProviders.ps1 present' (Test-Path -LiteralPath $provPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

. $provPath
T 'Resolve-PimPrincipalId loaded'    ([bool](Get-Command Resolve-PimPrincipalId -ErrorAction SilentlyContinue))
T 'Get-PimTargetDefaultDomain loaded' ([bool](Get-Command Get-PimTargetDefaultDomain -ErrorAction SilentlyContinue))

# ---------------------------------------------------------------------------
# STUBS: a fake Graph + counters. The "tenant" knows exactly two real users:
#   * realupn@slave.example          -> id-real
#   * PIMSCEN-Admin-X@slave.example  -> id-admin   (the bare name only resolves via fallback)
# /organization returns the slave tenant's verifiedDomains (default = slave.example).
# ---------------------------------------------------------------------------
$script:DefaultDomain = 'slave.example'
$script:Users = @{
    'realupn@slave.example'        = 'id-real'
    'PIMSCEN-Admin-X@slave.example' = 'id-admin'
}
$script:OrgCalls  = 0   # how many times /organization was hit (proves caching)
$script:UserCalls = 0   # how many /users lookups were attempted

# Reset the per-run domain cache between scenarios (the engine sets these per process run).
function Reset-DomainCache {
    Remove-Variable -Scope Script -Name __pimTargetDefaultDomain -ErrorAction SilentlyContinue
    Remove-Variable -Scope Script -Name __pimTargetDefaultDomainTried -ErrorAction SilentlyContinue
    # the function uses module/script scope of the PROVIDER file (dot-sourced into THIS
    # script's scope), so clearing the script-scope vars here resets it.
}

function Invoke-PimGraph {
    param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{})
    if ($Path -match '^/organization') {
        $script:OrgCalls++
        return ,([pscustomobject]@{ verifiedDomains = @(
            [pscustomobject]@{ name = 'slave.onmicrosoft.com'; isDefault = $false; isInitial = $true }
            [pscustomobject]@{ name = $script:DefaultDomain;   isDefault = $true;  isInitial = $false }
        ) })
    }
    if ($Path -match '^/users/') {
        $script:UserCalls++
        $enc = ($Path -replace '^/users/','') -replace '\?.*$',''
        $upn = [uri]::UnescapeDataString($enc)
        if ($script:Users.ContainsKey($upn)) { return [pscustomobject]@{ id = $script:Users[$upn]; userPrincipalName = $upn } }
        throw "Request_ResourceNotFound: user '$upn' (simulated 404)"
    }
    throw "stub Invoke-PimGraph: unexpected path $Path"
}
function Add-PimContextObject { param($Kind,$Object) }   # no-op cache sink

# ===========================================================================
# (1) A real UPN resolves DIRECTLY -- unchanged behaviour, no fallback/domain query.
# ===========================================================================
Write-Host "`n-- (1) real UPN resolves directly (unchanged) --" -ForegroundColor Cyan
Reset-DomainCache; $script:OrgCalls = 0; $script:UserCalls = 0
$id1 = Resolve-PimPrincipalId 'realupn@slave.example'
T '(1) real UPN resolves to its id'             ($id1 -eq 'id-real')
T '(1) direct hit makes exactly one /users call' ($script:UserCalls -eq 1)
T '(1) NO /organization query for a real UPN'    ($script:OrgCalls -eq 0)

# A GUID still passes straight through (no lookup at all).
$guid = '11111111-2222-3333-4444-555555555555'
$script:OrgCalls = 0; $script:UserCalls = 0
$idG = Resolve-PimPrincipalId $guid
T '(1) GUID passes through unchanged'            ($idG -eq $guid)
T '(1) GUID triggers no Graph calls'             ($script:UserCalls -eq 0 -and $script:OrgCalls -eq 0)

# ===========================================================================
# (2) A bare UserName that 404s on the direct lookup resolves via the fallback
#     UserName@<defaultDomain>.
# ===========================================================================
Write-Host "`n-- (2) bare UserName resolves via UserName@<defaultDomain> --" -ForegroundColor Cyan
Reset-DomainCache; $script:OrgCalls = 0; $script:UserCalls = 0
$id2 = Resolve-PimPrincipalId 'PIMSCEN-Admin-X'
T '(2) bare UserName resolves to the slave-tenant admin id' ($id2 -eq 'id-admin')
T '(2) default domain WAS queried for the fallback'         ($script:OrgCalls -eq 1)
# two /users calls: the failed direct bare lookup + the successful UPN fallback.
T '(2) direct bare lookup tried first, then the UPN'        ($script:UserCalls -eq 2)

# ===========================================================================
# (3) A bare UserName that resolves NOWHERE returns $null -- no crash, no wrong match.
# ===========================================================================
Write-Host "`n-- (3) genuinely-unknown bare UserName -> unresolved (no crash) --" -ForegroundColor Cyan
Reset-DomainCache; $script:OrgCalls = 0; $script:UserCalls = 0
$threw = $false; $id3 = 'sentinel'
try { $id3 = Resolve-PimPrincipalId 'PIMSCEN-Admin-DOESNOTEXIST' } catch { $threw = $true }
T '(3) unknown bare UserName does NOT throw'     (-not $threw)
T '(3) unknown bare UserName returns $null'      ($null -eq $id3)
T '(3) it did try the fallback (domain queried)' ($script:OrgCalls -eq 1)

# Empty / null input is still a clean $null.
T '(3) empty input -> $null (no throw)'          ($null -eq (Resolve-PimPrincipalId ''))
T '(3) $null input -> $null (no throw)'          ($null -eq (Resolve-PimPrincipalId $null))

# ===========================================================================
# (4) The default domain is fetched ONCE and cached across many fallback resolves.
# ===========================================================================
Write-Host "`n-- (4) default domain fetched once / cached --" -ForegroundColor Cyan
Reset-DomainCache; $script:OrgCalls = 0; $script:UserCalls = 0
$null = Resolve-PimPrincipalId 'PIMSCEN-Admin-X'         # first fallback -> queries /organization
$null = Resolve-PimPrincipalId 'PIMSCEN-Admin-DOESNOTEXIST'  # second fallback -> must NOT re-query
$null = Resolve-PimPrincipalId 'PIMSCEN-Admin-X'         # third fallback   -> must NOT re-query
T '(4) /organization queried exactly ONCE across 3 fallbacks' ($script:OrgCalls -eq 1)

# Direct cache helper also returns the same value on repeat without re-querying.
Reset-DomainCache; $script:OrgCalls = 0
$d1 = Get-PimTargetDefaultDomain
$d2 = Get-PimTargetDefaultDomain
T '(4) Get-PimTargetDefaultDomain returns the default domain' ($d1 -eq $script:DefaultDomain -and $d2 -eq $script:DefaultDomain)
T '(4) repeated calls hit the cache (one /organization call)' ($script:OrgCalls -eq 1)

# A miss (no default domain available) is cached too -- never re-queried, never throws.
Write-Host "`n-- (4b) a domain miss is cached (no re-query, no throw) --" -ForegroundColor Cyan
Reset-DomainCache; $script:OrgCalls = 0
$savedDom = $script:DefaultDomain
function Invoke-PimGraph {
    param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{})
    if ($Path -match '^/organization') { $script:OrgCalls++; return ,([pscustomobject]@{ verifiedDomains = @() }) }  # no domains
    throw "Request_ResourceNotFound (simulated)"
}
$miss1 = Get-PimTargetDefaultDomain
$miss2 = Get-PimTargetDefaultDomain
T '(4b) domain miss returns $null'               ($null -eq $miss1 -and $null -eq $miss2)
T '(4b) domain miss queried /organization once'  ($script:OrgCalls -eq 1)

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
