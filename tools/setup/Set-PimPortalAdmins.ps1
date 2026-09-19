#Requires -Version 5.1
<#
.SYNOPSIS
  DEPLOY-3 / SEC-15 -- install portal-admin profiles into the store. The supported way to set the
  delegation authorization model.

.DESCRIPTION
  §36.3 phase 2 made a hosted deployment read portal profiles from `pim.Settings` ONLY -- no file,
  no sample -- because an authorization model that falls back to a filesystem is one writable file
  away from being somebody else's. That closed the hole and left a gap:

  🪤 **THERE WAS NO SUPPORTED WAY TO INSTALL THE PROFILES.** Hit directly on 2026-08-31 while
  setting up the operator's own test identities: the profiles could be composed, and there was
  nowhere to put them except a hand-written JSON file (the thing being removed) or a manual SQL
  write. A deployment whose authorization model can only be installed by hand is not deployable --
  DEPLOY-3.

  This script is that path. It is deliberately NOT a wizard: profiles are authored as JSON (they
  are structured, reviewable, and belong in change control) and this installs them idempotently.

  🔒 MERGE, NOT REPLACE, BY DEFAULT. Profiles are keyed on `identity`. An identity in the input
  replaces its stored twin; identities NOT named are left alone. Installing one person's profile
  must never silently revoke everybody else's -- that is a self-inflicted outage on the
  authorization path. Use -Replace to impose a whole set deliberately.

  🔒 A READ FAILURE IS FATAL, never "nothing was there". Treating an unreadable store as empty
  would discard every existing profile on the next run -- the ESTATE-14 class, and on this table it
  would be an access-control wipe.

.PARAMETER ProfilesJson
  Path to a JSON file shaped like `{ "portalAdmins": [ {...}, {...} ] }`, or the raw JSON string.
  Each profile: identity (UPN or DOMAIN\user), displayName, services[], tierMax, levelMax,
  scopes[], capabilities[], managedAdmins[], managedGroupTags[].

.PARAMETER Replace
  Impose the supplied set as the WHOLE model, dropping stored identities not named in it.
  Off by default, and it prints exactly which identities it is about to remove.

.PARAMETER WhatIf
  Show what would change and write nothing.

.EXAMPLE
  pwsh -File Set-PimPortalAdmins.ps1 -TenantId <t> -SqlServerFqdn sql-x.database.windows.net `
       -AdminAppId <appid> -AdminCertThumbprint <thumb> -ProfilesJson .\profiles.json -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$AdminAppId,
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    [Parameter(Mandatory)][string]$ProfilesJson,
    [switch]$Replace,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')

$result = [ordered]@{ ok = $false; reason = ''; installed = @(); removed = @(); unchanged = @(); whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM portal-admin profiles -> pim.Settings['PortalAdmins'] ===" -ForegroundColor Cyan

# --- parse the input FIRST: never touch the store for input we cannot read ----
$raw = $ProfilesJson
if (Test-Path -LiteralPath $ProfilesJson) { $raw = Get-Content -LiteralPath $ProfilesJson -Raw -Encoding UTF8 }
$incoming = @()
try {
    $p = $raw | ConvertFrom-Json
    $incoming = @(if ($p.PSObject.Properties['portalAdmins']) { $p.portalAdmins } else { $p })
} catch {
    $result.reason = "input is not valid JSON: $($_.Exception.Message)"
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1
}
$bad = @($incoming | Where-Object { -not "$($_.identity)".Trim() })
if ($bad.Count) {
    # A profile with no identity can never match anyone, so it is silently dead weight in the
    # authorization model -- exactly the sort of thing that is discovered months later.
    $result.reason = "$($bad.Count) profile(s) have no 'identity' -- a profile that matches nobody is not a profile"
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1
}
if (-not $incoming.Count) {
    $result.reason = 'no profiles in the input'
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1
}
Note ("input: " + $incoming.Count + " profile(s) -- " + (($incoming | ForEach-Object { "$($_.identity)" }) -join ', ')) 'DarkGray'

# --- connect (explicit credential beats ambient MI -- BUG-34) -----------------
$global:PIM_TenantId    = $TenantId
$global:PIM_ClientId    = $AdminAppId
$global:PIM_SqlServer   = $SqlServerFqdn
$global:PIM_SqlDatabase = $SqlDatabase
if ("$AdminSecret".Trim())         { $global:PIM_ClientSecret   = $AdminSecret }
if ("$AdminCertThumbprint".Trim()) { $global:PIM_CertThumbprint = $AdminCertThumbprint }
if (-not "$AdminSecret".Trim() -and -not "$AdminCertThumbprint".Trim()) {
    $result.reason = 'no -AdminSecret and no -AdminCertThumbprint'
    Write-ResultFile; Write-Host "RESULT: FAILED -- supply -AdminSecret or -AdminCertThumbprint" -ForegroundColor Red; exit 1
}
try { $cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $SqlDatabase }
catch { $result.reason = "could not build a connection string: $($_.Exception.Message)"; Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1 }

# --- read what is already there ---------------------------------------------
$stored = @()
try {
    $cur = Get-PimSqlSetting -ConnectionString $cs -Name 'PortalAdmins'
    if ($cur) {
        if ($cur -is [string]) { $cur = $cur | ConvertFrom-Json }
        $stored = @(if ($cur.PSObject.Properties['portalAdmins']) { $cur.portalAdmins } else { $cur })
    }
} catch {
    # 🔒 FATAL. "Could not read" is not "nothing is stored" -- on this table that difference is an
    # access-control wipe.
    $result.reason = "could not read the existing PortalAdmins setting: $($_.Exception.Message)"
    Write-ResultFile
    Write-Host "RESULT: FAILED -- $($result.reason)  (refusing to overwrite an unread authorization model)" -ForegroundColor Red
    exit 1
}
Note ("already stored: " + $(if (@($stored).Count) { (@($stored) | ForEach-Object { "$($_.identity)" }) -join ', ' } else { '(none)' })) 'DarkGray'

# --- merge (or replace, deliberately) ----------------------------------------
$byId = [ordered]@{}
if (-not $Replace) { foreach ($s in @($stored)) { $byId["$($s.identity)".ToLowerInvariant()] = $s } }
foreach ($i in $incoming) {
    $k = "$($i.identity)".ToLowerInvariant()
    if ($byId.Contains($k)) { $result.unchanged += "$($i.identity) (replaced)" } else { $result.installed += "$($i.identity)" }
    $byId[$k] = $i
}
if ($Replace) {
    $dropped = @(@($stored) | Where-Object { -not $byId.Contains("$($_.identity)".ToLowerInvariant()) } | ForEach-Object { "$($_.identity)" })
    $result.removed = $dropped
    if ($dropped.Count) { Note ("-Replace WILL REMOVE: " + ($dropped -join ', ')) 'Yellow' }
}
$final = @($byId.Values)
Note ("resulting model: " + $final.Count + " profile(s)") 'Gray'

# --- REQ-Y: delegated administration ceilings are Pro (hard) -------------------------------------------------------
# A NEW or CHANGED profile needs a Pro licence bound to this tenant (pim.Settings['License'], verified offline). Removing
# profiles (-Replace with fewer) and re-writing an unchanged one stay free: a ceiling only ever RESTRICTS, so nothing
# here may widen anybody's access, and nobody is locked out of their own.
$storedById = @{}; foreach ($s in @($stored)) { $storedById["$($s.identity)".ToLowerInvariant()] = (ConvertTo-Json -InputObject $s -Depth 8 -Compress) }
$changedProfiles = @($incoming | Where-Object { $k = "$($_.identity)".ToLowerInvariant(); -not $storedById.ContainsKey($k) -or $storedById[$k] -ne (ConvertTo-Json -InputObject $_ -Depth 8 -Compress) })
if ($changedProfiles.Count) {
    . (Join-Path $sol 'engine\_shared\PIM-License.ps1')
    $licRaw = $null; $licErr = ''
    try { $licRaw = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT ValueJson FROM pim.Settings WHERE Name = N'License'" } catch { $licErr = "$($_.Exception.Message)" }
    $lic = Test-PimProLicence -FeatureNames @('PortalAdmins') -Label 'Delegated administration ceilings' -TenantId $TenantId -SqlServer $SqlServerFqdn -LicenseText (ConvertFrom-PimLicenseSettingRaw $licRaw) -StoreError $licErr
    if (-not $lic.ok) {
        $result.reason = "$($lic.message)"
        Write-ResultFile; Write-Host "RESULT: REFUSED -- $($lic.message)" -ForegroundColor Red; exit 2
    }
    if ($lic.grace) { Write-Host "WARNING: $($lic.message)" -ForegroundColor Yellow }
}

if ($WhatIfPreference) {
    $result.ok = $true; $result.reason = 'what-if -- nothing written'
    Write-ResultFile; Write-Host "RESULT: WHAT-IF -- nothing written" -ForegroundColor Yellow; exit 0
}

if ($PSCmdlet.ShouldProcess("pim.Settings['PortalAdmins']", "write $($final.Count) profile(s)")) {
    Set-PimSqlSetting -ConnectionString $cs -Name 'PortalAdmins' -Value ([ordered]@{ portalAdmins = $final })
}

# --- READ BACK. A write that is not verified is a hope, not a deploy step. ----
$verified = 0
try {
    $back = Get-PimSqlSetting -ConnectionString $cs -Name 'PortalAdmins'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    $verified = @(if ($back.PSObject.Properties['portalAdmins']) { $back.portalAdmins } else { $back }).Count
} catch {
    $result.reason = "wrote, but could not read back: $($_.Exception.Message)"
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1
}
if ($verified -ne $final.Count) {
    $result.reason = "read-back mismatch: wrote $($final.Count), store returned $verified"
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)" -ForegroundColor Red; exit 1
}

$result.ok = $true
$result.reason = "installed $($result.installed.Count), replaced $($result.unchanged.Count), removed $($result.removed.Count); store now holds $verified"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
Write-Host "  NOTE: profiles apply to non-SuperAdmin callers. A SuperAdmin bypasses all of this," -ForegroundColor DarkGray
Write-Host "        so give a test identity a PROFILE rather than SuperAdmin if you want to see" -ForegroundColor DarkGray
Write-Host "        level narrowing actually happen." -ForegroundColor DarkGray
exit 0
