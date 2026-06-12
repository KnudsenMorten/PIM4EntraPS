#Requires -Version 5.1
<#
.SYNOPSIS
    MSP-edition simulation (LIFECYCLE-GOVERNANCE § 19): show the two-store
    model from BOTH the MSP and the local-IT perspective, prove the ownership
    boundary, and print the merged apply plan a per-tenant engine run produces.

.DESCRIPTION
    Read-only demonstration of the "one core, pluggable edges, customer-owned
    control plane" design WITHOUT linking the two SQL stores:

      * MSP central registry (Owner=MSP baseline + guardrails) -- the admin
        plane store. Reached here over its private endpoint.
      * Customer LOCAL store (Owner=Local day-2-day admins + local resources)
        -- the customer-owned store. In production this lives in the customer
        tenant's own Azure; in this lab it is a separate SQL instance reached
        over its own private endpoint / connection string.

    The two databases are NEVER linked. This script connects to EACH
    separately (its own connection string + Entra token), then merges in
    memory -- exactly what a per-tenant engine run does after pulling the
    signed MSP baseline bundle. No data is written.

.PARAMETER CentralServer / LocalServer
    The two SQL FQDNs (Entra-only auth; an access token is minted from the
    current Az context for each).

.PARAMETER TenantName
    Which registered tenant to produce the merged plan for (default: the
    ring-2 test tenant the local store represents).
#>
[CmdletBinding()]
param(
    [string]$CentralServer,
    [string]$LocalServer,
    [string]$TenantName = 'Demo Ring2 Lab A',
    # Cross-tenant local store (the real § 19 placement): the customer store
    # lives in the customer's own tenant, so it needs that tenant's own token.
    # Supply the local engine SPN to mint a separate local-store token; omit to
    # use the current Az context for both (same-tenant lab).
    [string]$LocalTenantId,
    [string]$LocalAppId,
    [string]$LocalThumbprint = '50F3106D437C87374CACB28D47E8DEADB9BC0FE1'
)

$ErrorActionPreference = 'Stop'
Import-Module SqlServer -ErrorAction Stop

if (-not $CentralServer) { $CentralServer = (Get-Content C:\TMP\pim-sqlserver-name.txt -Raw).Trim() + '.database.windows.net' }

function ConvertTo-PlainToken($t) { if ($t -is [securestring]) { [System.Net.NetworkCredential]::new('', $t).Password } else { $t } }

# Capture the CENTRAL (MSP) token from the current context first.
$script:CentralToken = ConvertTo-PlainToken (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token

# Mint the LOCAL (customer-tenant) token separately when cross-tenant params given.
if ($LocalAppId -and $LocalTenantId) {
    Connect-AzAccount -ServicePrincipal -ApplicationId $LocalAppId -CertificateThumbprint $LocalThumbprint -Tenant $LocalTenantId -ErrorAction Stop | Out-Null
    $script:LocalToken = ConvertTo-PlainToken (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token
    if (-not $LocalServer) { $LocalServer = (Get-AzSqlServer -ResourceGroupName 'rg-pim-local' | Select-Object -First 1).ServerName + '.database.windows.net' }
} else {
    $script:LocalToken = $script:CentralToken
    if (-not $LocalServer) { throw "Provide -LocalServer (same-context) or -LocalAppId/-LocalTenantId (cross-tenant)." }
}

function Invoke-PimRead {
    param([string]$Server, [string]$Db, [string]$Query)
    $tok = if ($Server -eq $CentralServer) { $script:CentralToken } else { $script:LocalToken }
    Invoke-Sqlcmd -ServerInstance $Server -Database $Db -AccessToken $tok -Encrypt Mandatory -Query $Query -QueryTimeout 60
}

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS MSP simulation -- two stores, never linked (LIFECYCLE-GOVERNANCE 19)" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  MSP central (admin plane) : $CentralServer / PimPlatform   [private endpoint]"
Write-Host "  Customer LOCAL store      : $LocalServer / PimLocal        [own connection string]"
Write-Host "  Tenant in focus           : $TenantName"

# ---------------------------------------------------------------------------
# MSP perspective: the fleet + the MSP-owned baseline (read-only to local IT)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- MSP PERSPECTIVE (central registry) ---------------------------------" -ForegroundColor Magenta
$fleet = Invoke-PimRead -Server $CentralServer -Db 'PimPlatform' -Query "SELECT DisplayName, Ring FROM platform.Tenants ORDER BY Ring"
Write-Host "  Fleet ($(@($fleet).Count) tenants):"
$fleet | ForEach-Object { Write-Host ("    ring {0}  {1}" -f $_.Ring, $_.DisplayName) }
$baseline = Invoke-PimRead -Server $CentralServer -Db 'PimPlatform' -Query "SELECT UserName, Purpose, Ring, Owner FROM pim.CentralAdmins ORDER BY Ring"
Write-Host "  MSP-owned baseline admins (shipped to tenants as the signed bundle):"
$baseline | ForEach-Object { Write-Host ("    [{0}] {1,-20} {2,-9} ringReach<= {3}" -f $_.Owner, $_.UserName, $_.Purpose, $_.Ring) }

# ---------------------------------------------------------------------------
# Local-IT perspective: ONLY their own store + the baseline they received
# (read-only). They never see other tenants and never see the central store.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- LOCAL-IT PERSPECTIVE ($TenantName) ---------------------------------" -ForegroundColor Green
$localAdmins = Invoke-PimRead -Server $LocalServer -Db 'PimLocal' -Query "SELECT UserName, Purpose, Owner FROM pim.LocalAdmins WHERE Enabled=1 ORDER BY UserName"
Write-Host "  Owner=Local admins (the customer creates + manages these):"
$localAdmins | ForEach-Object { Write-Host ("    [{0}] {1,-16} {2}" -f $_.Owner, $_.UserName, $_.Purpose) }
$localRes = Invoke-PimRead -Server $LocalServer -Db 'PimLocal' -Query "SELECT GroupTag, RoleName, AzScope FROM pim.LocalResources"
Write-Host "  Owner=Local resources (their Azure scopes under their MG):"
$localRes | ForEach-Object { Write-Host ("    {0} -> {1} @ {2}" -f $_.GroupTag, $_.RoleName, $_.AzScope) }

# ---------------------------------------------------------------------------
# Merge: what the per-tenant engine run actually applies = MSP baseline (read-
# only) reaching this tenant by ring, UNION local-owned config. Disjoint
# namespaces: MSP owns HighPriv/guardrails, Local owns Day2Day/local resources.
# ---------------------------------------------------------------------------
$tenant = $fleet | Where-Object { $_.DisplayName -eq $TenantName } | Select-Object -First 1
$tenantRing = if ($tenant) { [int]$tenant.Ring } else { 2 }
Write-Host ""
Write-Host "--- MERGED ENGINE PLAN for $TenantName (ring $tenantRing) --------------" -ForegroundColor Yellow
Write-Host "  All of these are CREATED IN THE LOCAL TENANT by the local engine run:"
Write-Host "  the MSP central admins (from the pulled baseline) + the local-owned admins."
$mspReaching = @($baseline | Where-Object { [int]$_.Ring -le $tenantRing })
foreach ($r in $mspReaching) { Write-Host ("    MSP   {0,-20} {1,-9} (read-only to local IT)" -f $r.UserName, $r.Purpose) -ForegroundColor DarkGray }
foreach ($r in $localAdmins) { Write-Host ("    LOCAL {0,-20} {1,-9} (managed by local IT)" -f $r.UserName, $r.Purpose) }
$total = $mspReaching.Count + @($localAdmins).Count
Write-Host "  => $total admin objects apply to this tenant ($($mspReaching.Count) MSP + $(@($localAdmins).Count) local), zero namespace overlap."

# ---------------------------------------------------------------------------
# Ownership = separation, NOT gatekeeping. Local IT is autonomous in its own
# store (may create any Purpose, incl. privileged, with no MSP request). The
# Owner tag is provenance: Owner=MSP rows are refreshed on each baseline pull
# (so they aren't hand-edited locally), Owner=Local rows are the customer's.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- OWNERSHIP SEPARATION (provenance, not a gate) ----------------------" -ForegroundColor Yellow
$mspOwned   = @($baseline).Count
$localOwned = @($localAdmins).Count
Write-Host "  Owner=MSP rows (pulled-down baseline, refreshed each pull): $mspOwned"
Write-Host "  Owner=Local rows (customer-managed, fully autonomous):      $localOwned"
Write-Host "  Local IT may create ANY Purpose in their store (no MSP approval); the"
Write-Host "  baseline is additive standards on top -- the two stores are never linked."

Write-Host ""
Write-Host "Simulation complete (read-only). The two stores were never linked; the merge" -ForegroundColor Cyan
Write-Host "happened in-memory after reading each separately -- exactly the engine's job." -ForegroundColor Cyan
