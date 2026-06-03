#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Test the PIM-for-Groups bulk-activation flow WITHOUT loading the Edge
    extension. Exercises the same Graph API calls the popup makes, against
    the same delegated permission set.

.DESCRIPTION
    Mirrors what tools/pim-activator/popup.js does at runtime:
      1. Interactive sign-in as the calling user (delegated PrivilegedAccess.
         ReadWrite.AzureADGroup + Group.Read.All -- the same scopes the
         activator app reg requests).
      2. List the user's PIM-for-Groups eligibility schedules tenant-wide.
      3. Resolve each groupId -> displayName (best-effort).
      4. Interactive multi-select prompt.
      5. POST a self-activation request per selected group with justification
         + duration.

    If this script succeeds, the extension will succeed too -- they use the
    identical Graph endpoints with the identical scopes. If this script fails
    on a specific row, the same row will fail in the extension popup.

.PARAMETER TenantId
    Tenant to sign into (the customer tenant where your eligible PIM-for-
    Groups assignments live).

.PARAMETER GroupNameFilter
    Regex to limit which groups appear. Default '^PIM-' matches the
    PIM4EntraPS naming convention.

.PARAMETER DurationHours
    Activation duration in hours. Default 1. Tenant policy may cap.

.PARAMETER Justification
    Text to send with the activation request. Default 'Test from
    Test-PimActivatorFlow.ps1'.

.EXAMPLE
    .\Test-PimActivatorFlow.ps1 -TenantId 'f0fa27a0-...'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [string] $GroupNameFilter = '^PIM-',
    [ValidateRange(1,24)][int] $DurationHours = 1,
    [string] $Justification = 'Test from Test-PimActivatorFlow.ps1'
)

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "=== PIM Activator flow test ===" -ForegroundColor Cyan
Write-Host "  Tenant       : $TenantId"
Write-Host "  Group filter : $GroupNameFilter"
Write-Host "  Duration     : $DurationHours hour(s)"
Write-Host "  Justification: $Justification"
Write-Host ""

# Step 1: Connect-MgGraph with delegated scopes (browser flow)
Write-Host "[ 1 / 4 ] Signing in (delegated, browser) ..." -ForegroundColor Yellow
$wantScopes = @('PrivilegedAccess.ReadWrite.AzureADGroup', 'Group.Read.All', 'User.Read')
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
} catch {}
Connect-MgGraph -TenantId $TenantId -Scopes $wantScopes -NoWelcome

$ctx = Get-MgContext
Write-Host "[ 1 / 4 ] OK -- signed in as $($ctx.Account) on $($ctx.TenantId)" -ForegroundColor Green

# Get the signed-in user's object id (PIM eligibility is keyed by principalId)
$me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,displayName'
$myId  = $me.id
$myUpn = $me.userPrincipalName
Write-Host "          You are principalId $myId  ($myUpn)" -ForegroundColor DarkGray
Write-Host ""

# Step 2: list MY PIM-for-Groups eligibility schedule INSTANCES
Write-Host "[ 2 / 4 ] Fetching your PIM-for-Groups eligibility instances ..." -ForegroundColor Yellow
$uri = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=principalId eq '$myId'"
$eligibilities = @()
do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    if ($resp.value) { $eligibilities += $resp.value }
    $uri = $resp.'@odata.nextLink'
} while ($uri)
Write-Host "[ 2 / 4 ] OK -- $($eligibilities.Count) eligibility row(s) found tenant-wide" -ForegroundColor Green

if ($eligibilities.Count -eq 0) {
    Write-Host ""
    Write-Host "Nothing to activate. Either:"  -ForegroundColor Yellow
    Write-Host "  - Your account isn't PIM-eligible for any group in this tenant"
    Write-Host "  - The eligibility was just created and Graph hasn't propagated yet (wait 1-2 min, re-run)"
    Disconnect-MgGraph | Out-Null
    return
}

# Step 3: resolve group display names + apply filter
Write-Host ""
Write-Host "[ 3 / 4 ] Resolving group display names + applying filter '$GroupNameFilter' ..." -ForegroundColor Yellow
$resolved = @()
foreach ($e in $eligibilities) {
    try {
        $g = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($e.groupId)?`$select=id,displayName,description"
        $resolved += [pscustomobject]@{
            GroupId      = $e.groupId
            DisplayName  = $g.displayName
            Description  = $g.description
            AccessId     = $e.accessId
            AssignmentType = $e.assignmentType
            ScheduleId   = $e.eligibilityScheduleId
        }
    } catch {
        Write-Warning "  Group $($e.groupId) lookup failed: $($_.Exception.Message)"
    }
}
$filtered = $resolved | Where-Object { $_.DisplayName -match $GroupNameFilter -and $_.AccessId -eq 'member' }
Write-Host "[ 3 / 4 ] OK -- $($filtered.Count) row(s) match '$GroupNameFilter' (member access only)" -ForegroundColor Green

if ($filtered.Count -eq 0) {
    Write-Host ""
    Write-Host "Filter matched nothing. Try -GroupNameFilter '.*' to see ALL eligible groups (any name)." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "All eligible rows (unfiltered):"
    $resolved | Format-Table DisplayName, GroupId, AccessId, AssignmentType -AutoSize
    Disconnect-MgGraph | Out-Null
    return
}

# Step 4: interactive multi-select + activate
Write-Host ""
Write-Host "Eligible groups matching filter:" -ForegroundColor Cyan
for ($i = 0; $i -lt $filtered.Count; $i++) {
    Write-Host ("  [{0,2}] {1}  ({2})" -f ($i+1), $filtered[$i].DisplayName, $filtered[$i].GroupId)
}
Write-Host ""
$pickRaw = Read-Host "Pick row numbers to activate (comma-separated, e.g. 1,3,5  -- or ENTER to abort)"
if (-not $pickRaw -or -not $pickRaw.Trim()) {
    Write-Host "Aborted (no picks)." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}
$picks = $pickRaw -split ',' | ForEach-Object {
    $n = 0
    if ([int]::TryParse($_.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $filtered.Count) { $filtered[$n-1] }
}
if (-not $picks) {
    Write-Host "No valid picks. Aborted." -ForegroundColor Yellow
    Disconnect-MgGraph | Out-Null
    return
}

Write-Host ""
Write-Host "[ 4 / 4 ] Activating $($picks.Count) group(s) for $DurationHours hour(s) ..." -ForegroundColor Yellow
$results = @()
foreach ($p in $picks) {
    $body = @{
        accessId       = 'member'
        principalId    = $myId
        groupId        = $p.GroupId
        action         = 'selfActivate'
        scheduleInfo   = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            expiration    = @{
                type     = 'AfterDuration'
                duration = "PT${DurationHours}H"
            }
        }
        justification = $Justification
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        $resp = Invoke-MgGraphRequest -Method POST `
                  -Uri 'https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' `
                  -Body $body -ContentType 'application/json'
        Write-Host "  + $($p.DisplayName) -- ACTIVATED (request id $($resp.id))" -ForegroundColor Green
        $results += [pscustomobject]@{ Group = $p.DisplayName; OK = $true; RequestId = $resp.id; Status = $resp.status }
    } catch {
        $msg = $_.Exception.Message
        Write-Host "  X $($p.DisplayName) -- FAILED: $msg" -ForegroundColor Red
        $results += [pscustomobject]@{ Group = $p.DisplayName; OK = $false; Error = $msg }
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$ok = ($results | Where-Object OK).Count
$bad = ($results | Where-Object { -not $_.OK }).Count
Write-Host "  Activated: $ok"
Write-Host "  Failed   : $bad"
Write-Host ""
if ($ok -gt 0) {
    Write-Host "Verify in the Entra portal -> Identity governance -> PIM -> Groups -> Active assignments." -ForegroundColor DarkGray
}

Disconnect-MgGraph | Out-Null
