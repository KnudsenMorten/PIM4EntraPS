#Requires -Version 5.1

<#
.SYNOPSIS
  Set the PIM Manager SQL database to the right Standard tier with a 250 GB maximum size, and optionally pin its tier.
  -WhatIf shows the change first.

.DESCRIPTION
  Set the PIM Manager SQL database to the right Standard tier with a 250 GB maximum size, and optionally pin its tier so
  updates never change it.

  Owner 2026-10-09 ("pim sql is not req lot" / "fix setup scripts"; PIM REQUIREMENTS 100.37, framework 12.15): PIM's
  database is never Basic -- S0 (Standard) is the minimum, for every edition -- and every Standard database has a 250 GB
  maximum size (268435456000 bytes). Raising a tier does NOT raise the maximum size, so a database moved up from Basic kept
  Basic's 2 GB limit and stopped accepting writes ("has reached its size quota"). The installer and every update apply the
  same plan (Get-PimSqlTierPlan, engine/_shared/PIM-TenantSizing.ps1, embedded in the published file); this script applies
  it on demand:

    * without -Tier: THE PLAN -- Basic -> S0 (never on a database tagged pim-sql-tier-pin), any Standard database below
      250 GB -> 250 GB. A tier or a limit is never lowered; Premium, vCore and elastic-pool databases are not touched.
    * -Tier S0|S1|S2|...: the Standard tier you choose (never Basic), with the 250 GB maximum size. Changing the tier of a
      pinned database needs -Pin (which re-pins it to the new tier).
    * -Pin: tags the database pim-sql-tier-pin = <its tier>, so the updater never changes its tier (the 250 GB rule still
      applies). The database's other tags are kept.

  ONE PATCH of the database (sku {name; tier 'Standard'} and/or properties.maxSizeBytes and/or tags; ARM api-version
  2021-11-01), then it reads the database back until the tier and the maximum size are confirmed and it is Online; a 404
  or 5xx answer right after the PATCH is transient (the scale is running) and is waited out. Prints before and after.
  The tier is read from properties.currentServiceObjectiveName -- never from sku.name, which for a Standard database is
  the tier name "Standard", not "S0".

  Sign-in, no PowerShell module: with -TenantId in the BROWSER as you (or the Invardia Support app with -AdminAppId +
  -AdminSecret); without -TenantId the Invardia Support-app session's REST shim (a function -- the Az PowerShell
  cmdlet of the same name is never used). Published standalone at https://invardia.com/support/pim/Set-PimSqlTier.ps1.

.EXAMPLE
  .\Set-PimSqlTier.ps1 -SubscriptionId <subscription id> -ResourceGroup <resource group> -Server <sql server> -TenantId <tenant id> -WhatIf
  Preview the plan; then the same command without -WhatIf.

.EXAMPLE
  .\Set-PimSqlTier.ps1 -SubscriptionId <subscription id> -ResourceGroup <resource group> -Server <sql server> -TenantId <tenant id> -Tier S0 -Pin
  S0 with 250 GB, pinned so updates keep it on S0.

.LINK
  https://invardia.com/docs/pim/scripts/Set-PimSqlTier/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    # the SQL server name or its FQDN (sql-x or sql-x.database.windows.net)
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'PimPlatform',
    # a Standard objective (S0, S1, S2, S3, S4, S6, S7, S9, S12); never Basic
    [ValidatePattern('^(?i)S(0|1|2|3|4|6|7|9|12)$')][string]$Tier,
    [switch]$Pin,
    [string]$TenantId,
    [string]$AdminAppId,
    [string]$AdminSecret,
    [ValidateRange(1, 120)][int]$ReadBackMinutes = 20,
    [ValidateRange(0, 300)][int]$PollSeconds = 20
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimMailSetup.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-TenantSizing.ps1')
$null = Start-PimScriptRun -Script 'Set-PimSqlTier'
try {

$api = '2021-11-01'
$maxWant = [int64]268435456000
$srvName = ("$Server".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
if ($srvName -notmatch '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') { throw "Set-PimSqlTier: not a SQL server name: $Server" }
if ($Database -notmatch '^[^<>*%&:\\/?]{1,128}$') { throw "Set-PimSqlTier: not a database name: $Database" }
$dbPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Sql/servers/$srvName/databases/$Database"

# --- how to reach ARM ------------------------------------------------------------------------------------------------------
$mode = ''
if ("$AdminSecret".Trim() -or "$AdminAppId".Trim()) {
    $ap = Resolve-PimMailSetupAuthMode -AdminAppId $AdminAppId -AdminSecret $AdminSecret
    if ($ap.reason) { throw "Set-PimSqlTier: $($ap.reason)" }
    if (-not "$TenantId".Trim()) { throw 'Set-PimSqlTier: -TenantId is needed with -AdminAppId + -AdminSecret.' }
    $mode = 'secret'
} elseif ("$TenantId".Trim()) {
    if (-not (Test-PimMsInteractiveHost)) { throw 'Set-PimSqlTier: this run signs in in the BROWSER, and this session is not interactive -- run it in a PowerShell window, or pass -AdminAppId + -AdminSecret.' }
    $mode = 'browser'
} else {
    # REQ 100.42 (no PowerShell modules): the ONLY session path is the Invardia Support-app session's REST shim, which is a
    # FUNCTION named Invoke-AzRestMethod. The Az.Accounts CMDLET of the same name is never used: the lookup takes
    # functions only, and the call goes through the resolved command object, so it cannot resolve to the module.
    $sqtShim = Get-Command -Name ('Invoke-' + 'AzRestMethod') -CommandType Function -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sqtShim) { $mode = 'session' }
    else { throw 'Set-PimSqlTier: pass -TenantId (browser sign-in, or with -AdminAppId + -AdminSecret), or run it in an Invardia Support-app session.' }
}

function Get-SqtToken {
    $WhatIfPreference = $false   # the sign-in is a READ the preview needs
    if ($mode -eq 'secret') { return (Get-PimMsAppToken -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -Resource 'arm') }
    return (Get-PimMsBrowserToken -Resource 'arm' -TenantId $TenantId)
}
function Invoke-SqtArm([string]$Method = 'GET', [string]$Path, $Body) {
    # Returns @{ status; json; text } and never throws on an HTTP status (a 404 / 5xx mid-scale is the caller's call).
    $WhatIfPreference = $false
    $payload = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 8 -Compress } else { $null }
    if ($mode -eq 'session') {
        $a = @{ Method = $Method; Path = $Path }; if ($null -ne $payload) { $a.Payload = $payload }
        $r = & $sqtShim @a
        $txt = if ($r.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($r.Content) } else { "$($r.Content)" }
        $js = $null; if ($txt.Trim()) { try { $js = $txt | ConvertFrom-Json } catch { $js = $null } }
        return [pscustomobject]@{ status = [int]$r.StatusCode; json = $js; text = $txt }
    }
    $h = @{ Authorization = "Bearer $(Get-SqtToken)"; 'Content-Type' = 'application/json' }
    try {
        $a = @{ Method = $Method; Uri = "https://management.azure.com$Path"; Headers = $h }; if ($null -ne $payload) { $a.Body = $payload }
        $js = Invoke-RestMethod @a
        return [pscustomobject]@{ status = 200; json = $js; text = '' }
    } catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
        return [pscustomobject]@{ status = $(if ($code) { $code } else { 599 }); json = $null; text = ("$($_.Exception.Message) $($_.ErrorDetails.Message)" -replace '\s+', ' ').Trim() }
    }
}
function Show-SqtDb([string]$Label, $Db) {
    $p = $Db.properties
    $tg = @(); if ($Db.tags) { foreach ($t in $Db.tags.PSObject.Properties) { $tg += "$($t.Name)=$($t.Value)" } }
    Write-Host ("  {0} {1} ({2}, {3} DTU), max size {4}, status {5}, pin {6}" -f $Label, (Resolve-PimSqlServiceObjective -Database $Db), "$($Db.sku.tier)", "$($Db.sku.capacity)",
        $(if ("$($p.maxSizeBytes)" -match '^\d+$') { '{0:N0} GB' -f ([int64]$p.maxSizeBytes / 1GB) } else { 'unknown' }), "$($p.status)",
        $(if ($Db.tags -and $Db.tags.PSObject.Properties['pim-sql-tier-pin']) { "$($Db.tags.'pim-sql-tier-pin')" } else { 'none' }))
}

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- SQL DATABASE TIER + 250 GB MAX SIZE: $srvName / $Database" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# --- read ----------------------------------------------------------------------------------------------------------------
$g = Invoke-SqtArm -Path "$dbPath`?api-version=$api"
if ($g.status -ge 400 -or -not $g.json) { throw "Set-PimSqlTier: could not read the database $dbPath (HTTP $($g.status)): $($g.text)" }
$db = $g.json
Show-SqtDb 'before:' $db
$cur = Resolve-PimSqlServiceObjective -Database $db
$curMax = $null; if ("$($db.properties.maxSizeBytes)" -match '^\d+$') { $curMax = [int64]$db.properties.maxSizeBytes }
$pinNow = $null; if ($db.tags -and $db.tags.PSObject.Properties['pim-sql-tier-pin']) { $pinNow = "$($db.tags.'pim-sql-tier-pin')" }
$pool = "$($db.properties.elasticPoolId)"

# --- decide (the ONE plan; -Tier is your own choice of Standard tier) -----------------------------------------------------
$targetTier = $cur; $tierChange = $false
if ("$Tier".Trim()) {
    if ($pool) { throw "Set-PimSqlTier: the database is in an elastic pool ($pool) -- its tier is the pool's; not changed." }
    if ($cur -notmatch '^(?i)(Basic|S\d+)$') { throw "Set-PimSqlTier: the database is '$cur' (not Basic / Standard) -- this script sets Standard tiers only; not changed." }
    if ($pinNow -and $pinNow -ine $Tier.ToUpperInvariant() -and -not $Pin) { throw "Set-PimSqlTier: the database is pinned to '$pinNow' (pim-sql-tier-pin). Add -Pin to change its tier to $($Tier.ToUpperInvariant()) and re-pin it." }
    $targetTier = $Tier.ToUpperInvariant(); $tierChange = ($targetTier -ine $cur)
    $mp = Get-PimSqlTierPlan -Current $targetTier -CurrentMaxSizeBytes $(if ($cur -match '^(?i)basic$' -and $null -eq $curMax) { 1 } else { $curMax })
    $why = "-Tier $targetTier (your choice)"
} else {
    $mp = Get-PimSqlTierPlan -Current $cur -ElasticPool $pool -CurrentMaxSizeBytes $curMax -Pin $pinNow
    if ($mp.action -eq 'raise') { $targetTier = $mp.target; $tierChange = $true }
    $why = "$($mp.reason)"
}
$maxSet = ($mp.maxSizeAction -eq 'set')
$pinTag = $(if ($Pin) { $targetTier } else { $null })
$pinChange = ($Pin -and "$pinNow" -cne "$pinTag")
if ($Pin -and $targetTier -notmatch '^(?i)S\d+$') { throw "Set-PimSqlTier: -Pin pins a Standard tier; the database is '$targetTier'." }
Write-Host "  plan:   $why" -ForegroundColor DarkGray

if (-not $tierChange -and -not $maxSet -and -not $pinChange) { Write-Host "`nRESULT: nothing to change -- $targetTier, max size kept$(if ($pinNow) { ", pinned to $pinNow" })." -ForegroundColor Green; exit 0 }

$body = @{}
$what = @()
if ($tierChange) { $body['sku'] = @{ name = $targetTier; tier = 'Standard' }; $what += "tier $cur -> $targetTier" }
if ($maxSet) { $body['properties'] = @{ maxSizeBytes = $maxWant }; $what += ("max size {0} -> 250 GB" -f $(if ($null -ne $curMax) { '{0:N0} GB' -f ($curMax / 1GB) } else { 'unknown' })) }
if ($pinChange) {
    $tags = @{}; if ($db.tags) { foreach ($t in $db.tags.PSObject.Properties) { $tags[$t.Name] = "$($t.Value)" } }
    $tags['pim-sql-tier-pin'] = $pinTag
    $body['tags'] = $tags; $what += "tag pim-sql-tier-pin = $pinTag"
}
if (-not $PSCmdlet.ShouldProcess("SQL database $srvName/$Database", "update: $($what -join '; ')")) { Write-Host "`nRESULT: preview only -- nothing was changed." -ForegroundColor DarkYellow; exit 0 }

# --- change: ONE PATCH ---------------------------------------------------------------------------------------------------
$p = Invoke-SqtArm -Method PATCH -Path "$dbPath`?api-version=$api" -Body $body
if ($p.status -ge 400) { throw "Set-PimSqlTier: the database update was refused (HTTP $($p.status)): $($p.text)" }
Write-Host "  update accepted (HTTP $($p.status)): $($what -join '; ')" -ForegroundColor Green

# --- read back until confirmed (a 404 / 5xx right after a tier PATCH is transient: the scale is running) ---------------
$deadline = (Get-Date).AddMinutes($ReadBackMinutes); $done = $false; $a = $null
do {
    if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
    $r = Invoke-SqtArm -Path "$dbPath`?api-version=$api"
    if ($r.status -eq 404 -or $r.status -ge 500 -or -not $r.json) { Write-Host "  read-back: HTTP $($r.status) -- transient while the change runs, waiting" -ForegroundColor DarkGray; continue }
    $a = $r.json
    $aMax = 0L; [void][int64]::TryParse("$($a.properties.maxSizeBytes)", [ref]$aMax)
    $done = ((Resolve-PimSqlServiceObjective -Database $a) -ieq $targetTier -and (-not $maxSet -or $aMax -ge $maxWant) -and "$($a.properties.status)" -eq 'Online' -and
             (-not $pinChange -or ($a.tags -and "$($a.tags.'pim-sql-tier-pin')" -ceq $pinTag)))
} until ($done -or (Get-Date) -gt $deadline)
if ($a) { Show-SqtDb 'after: ' $a }
if (-not $done) { Write-Host "`nRESULT: NOT CONFIRMED within $ReadBackMinutes min -- a tier change can take longer; re-run with -WhatIf to read the current state." -ForegroundColor Yellow; exit 1 }
Write-Host "`nRESULT: done -- $targetTier, max size 250 GB$(if ($pinChange) { ", pinned to $pinTag" }) (read back)." -ForegroundColor Green
exit 0
} finally { Stop-PimScriptRun -Script 'Set-PimSqlTier' }
