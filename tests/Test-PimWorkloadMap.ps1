#Requires -Version 5.1
<#
.SYNOPSIS
    Offline unit tests for the workload live-crawl map + reconciliation
    (engine/_shared/PIM-WorkloadMap.ps1). PURE: no network, no SQL. Proves the
    desired-vs-live reconciliation that badges the Delegation Map's
    workload-target chips (mapped | missing | exempted | unknown), the exemption
    contract (mandatory reason + expiry; expired resurfaces as missing), and the
    crawl-map cache round-trip (writer normalisation via a stubbed connector API).

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-WorkloadMap.ps1'
T 'PIM-WorkloadMap.ps1 present' (Test-Path -LiteralPath $shared)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
. $shared

# Helper: a desired row object (PSCustomObject like Read-PimRows yields).
function Row([string]$wl, [string]$role, [string]$tag, [string]$scope) {
    [pscustomobject]@{ Workload = $wl; RoleName = $role; GroupTag = $tag; Scope = $scope; Action = 'Assign' }
}

# A crawl map with one live Defender assignment for group GID-1 (role + scope /).
$gid1 = '11111111-1111-1111-1111-111111111111'
$crawl = [pscustomobject]@{
    crawledUtc = '2026-06-18T10:00:00Z'
    workloads  = [pscustomobject]@{
        'defender-xdr' = [pscustomobject]@{
            ok = $true
            assignments = @(
                [pscustomobject]@{ roleId = 'rid-secop'; roleName = 'Security Operator'; scope = '/'; principalIds = @($gid1) }
            )
        }
        'intune' = [pscustomobject]@{ ok = $false; error = '403 Forbidden'; assignments = @() }
    }
}

# --- Reconciliation: mapped / missing / unknown -------------------------------
$rMapped = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Operator' 'TAG-1' '/') -CrawlMap $crawl -GroupId $gid1
T 'live+desired -> mapped'            ("$($rMapped.status)" -eq 'mapped')
T 'mapped carries crawledUtc'         ("$($rMapped.crawledUtc)" -eq '2026-06-18T10:00:00Z')

$rMissing = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Reader' 'TAG-2' '/') -CrawlMap $crawl -GroupId $gid1
T 'desired role not live -> missing'  ("$($rMissing.status)" -eq 'missing')

# GroupId mismatch -> the role exists live but for a different principal -> missing.
$rWrongGrp = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Operator' 'TAG-3' '/') -CrawlMap $crawl -GroupId '99999999-9999-9999-9999-999999999999'
T 'live role, other principal -> missing' ("$($rWrongGrp.status)" -eq 'missing')

# Without a GroupId, the recon falls back to role(+scope) presence -> mapped.
$rNoGid = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Operator' 'TAG-1' '/') -CrawlMap $crawl
T 'no GroupId falls back to role presence -> mapped' ("$($rNoGid.status)" -eq 'mapped')

# A workload whose crawl errored (intune) is UNKNOWN, never a false 'missing'.
$rUnknownErr = Get-PimWorkloadReconStatus -Row (Row 'intune' 'Help Desk Operator' 'TAG-4' '') -CrawlMap $crawl
T 'crawl errored -> unknown (not missing)' ("$($rUnknownErr.status)" -eq 'unknown')

# A workload with no crawl entry at all is UNKNOWN.
$rNoCrawl = Get-PimWorkloadReconStatus -Row (Row 'powerbi' 'Member' 'TAG-5' '') -CrawlMap $crawl
T 'no crawl entry -> unknown' ("$($rNoCrawl.status)" -eq 'unknown')

# No crawl map at all -> unknown.
$rNoMap = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Operator' 'TAG-1' '/') -CrawlMap $null
T 'no crawl map -> unknown' ("$($rNoMap.status)" -eq 'unknown')

# --- Exemptions ---------------------------------------------------------------
$future = (Get-Date).AddYears(1).ToString('yyyy-MM-dd')
$past   = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')

$exActive = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @(
    [pscustomobject]@{ workload = 'defender-xdr'; role = 'Security Reader'; reason = 'manual mgmt'; expiresOn = $future }
) }))
T 'exemption parsed' (@($exActive).Count -eq 1 -and "$($exActive[0].role)" -eq 'Security Reader')

$rExempt = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Reader' 'TAG-2' '/') -CrawlMap $crawl -GroupId $gid1 -Exemptions $exActive
T 'missing + active exemption -> exempted' ("$($rExempt.status)" -eq 'exempted')
T 'exempted carries reason'                ("$($rExempt.reason)" -eq 'manual mgmt')

# Expired exemption does NOT excuse -> resurfaces as missing.
$exExpired = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @(
    [pscustomobject]@{ workload = 'defender-xdr'; role = 'Security Reader'; reason = 'manual mgmt'; expiresOn = $past }
) }))
$rExpired = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Reader' 'TAG-2' '/') -CrawlMap $crawl -GroupId $gid1 -Exemptions $exExpired
T 'expired exemption -> missing (resurfaces)' ("$($rExpired.status)" -eq 'missing')

# Exemption missing mandatory reason is NOT active.
$exNoReason = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @(
    [pscustomobject]@{ workload = 'defender-xdr'; role = 'Security Reader'; expiresOn = $future }
) }))
$rNoReason = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Reader' 'TAG-2' '/') -CrawlMap $crawl -GroupId $gid1 -Exemptions $exNoReason
T 'exemption without reason -> not exempted (missing)' ("$($rNoReason.status)" -eq 'missing')

# Exemption with neither workload nor role is too broad -> never matches.
$exBroad = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @(
    [pscustomobject]@{ reason = 'all'; noExpiry = $true }
) }))
$rBroad = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Reader' 'TAG-2' '/') -CrawlMap $crawl -GroupId $gid1 -Exemptions $exBroad
T 'over-broad exemption ignored -> missing' ("$($rBroad.status)" -eq 'missing')

# noExpiry exemption is active indefinitely.
$exNoExpiry = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @(
    [pscustomobject]@{ workload = 'intune'; role = 'Help Desk Operator'; reason = 'manual'; noExpiry = $true }
) }))
T 'noExpiry exemption active' (Test-PimWorkloadExemptionActive -Exemption $exNoExpiry[0])

# --- Summary roll-up ----------------------------------------------------------
$rows = @(
    (Row 'defender-xdr' 'Security Operator' 'TAG-1' '/'),   # mapped (no GroupId match -> role presence)
    (Row 'defender-xdr' 'Security Reader'   'TAG-2' '/'),   # exempted (active exemption)
    (Row 'powerbi'      'Member'            'TAG-5' '')      # unknown (no crawl)
)
$summary = Get-PimWorkloadReconSummary -Rows $rows -CrawlMap $crawl -Exemptions $exActive
T 'summary total = 3'      ($summary.total -eq 3)
T 'summary mapped = 1'     ($summary.mapped -eq 1)
T 'summary exempted = 1'   ($summary.exempted -eq 1)
T 'summary unknown = 1'    ($summary.unknown -eq 1)
T 'summary carries crawledUtc' ("$($summary.crawledUtc)" -eq '2026-06-18T10:00:00Z')

# --- Crawl-map cache round-trip (writer normalisation, stubbed API) -----------
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("pim-wlmap-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$connDir = Join-Path $tmpDir 'connectors'
New-Item -ItemType Directory -Path $connDir -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$connJson = @'
{
  "id": "defender-xdr",
  "name": "Microsoft Defender XDR (Unified RBAC)",
  "auth": "graph",
  "api": {
    "baseUrl": "https://graph.microsoft.com/beta",
    "listRoles": { "method": "GET", "path": "/r", "itemsPath": "value", "roleId": "id", "roleName": "displayName" },
    "listAssignments": { "method": "GET", "path": "/a", "itemsPath": "value", "assignmentId": "id", "roleId": "roleDefinitionId", "principalIds": "principalIds" }
  }
}
'@
[System.IO.File]::WriteAllText((Join-Path $connDir 'defender-xdr.connector.json'), $connJson, $utf8)

try {
    # Stub the live-call helpers the crawl uses (so it is fully offline).
    function Read-PimWorkloadConnectors { param([string]$ConnectorsDir)
        @(Get-ChildItem $ConnectorsDir -Filter '*.connector.json' | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json })
    }
    function Get-PimNestedProp { param($Object, $Path) if (-not $Path) { return $null }; $c = $Object; foreach ($s in ($Path -split '\.')) { if ($null -eq $c) { return $null }; $c = $c.$s }; $c }
    function Get-PimWorkloadRoles { param($Connector, $Tokens) @(@{ id = 'rid-secop'; name = 'Security Operator'; description = '' }) }
    function Invoke-PimWorkloadApi { param($Connector, $Op, $Tokens, $Body)
        [pscustomobject]@{ value = @([pscustomobject]@{ id = 'asg-1'; roleDefinitionId = 'rid-secop'; principalIds = @($gid1); displayName = 'PIM4EntraPS: TAG-1 -> Security Operator'; directoryScopeIds = @('/') }) }
    }
    function Get-PimWorkloadAssignmentPrincipals { param($Connector, $Item) @{ id = "$($Item.id)"; principals = @($Item.principalIds); displayName = "$($Item.displayName)" } }

    $written = Update-PimWorkloadCrawlMap -ConnectorsDir $connDir -CacheDir $tmpDir
    T 'crawl map written' ($written -and (Test-Path -LiteralPath $written))

    $readBack = Read-PimWorkloadCrawlMap -CacheDir $tmpDir
    T 'crawl map reads back' ($null -ne $readBack)
    $df = $readBack.workloads.'defender-xdr'
    T 'crawl recorded ok=true' ($df -and $df.ok -eq $true)
    T 'crawl normalised role name' (@($df.assignments).Count -eq 1 -and "$($df.assignments[0].roleName)" -eq 'Security Operator')
    T 'crawl normalised principal' (@($df.assignments[0].principalIds) -contains $gid1)

    # And the read-back map reconciles a desired row to mapped.
    $rRoundtrip = Get-PimWorkloadReconStatus -Row (Row 'defender-xdr' 'Security Operator' 'TAG-1' '/') -CrawlMap $readBack -GroupId $gid1
    T 'round-trip crawl reconciles -> mapped' ("$($rRoundtrip.status)" -eq 'mapped')
} finally {
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
