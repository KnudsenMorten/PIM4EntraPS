#Requires -Version 5.1
<#
.SYNOPSIS
  DEPLOY-3 / SEC-15 -- install Manager RBAC (Reader / Admin / SuperAdmin / Delegated) into the
  store. The supported way to say who may use the Manager, and at what level.

.DESCRIPTION
  §36.3 phase 2 gave portal PROFILES an auditable home in `pim.Settings`. Manager RBAC -- the
  coarser question of whether you can write at all -- was still set as container app settings
  (`PIM_SuperAdmins` / `PIM_Admins` / `PIM_DelegatedAdmins`), by hand, with an
  `az containerapp update` somebody has to remember.

  🪤 Measured on this deployment 2026-08-31: `PIM_SuperAdmins` held exactly ONE identity and
  nothing in any script had put it there. Adding an administrator meant editing a container.
  App settings are better than a file -- versioned, access-controlled -- but it left the
  authorization model with **two homes and only one of them auditable**.

  This writes `pim.Settings['ManagerAccess']`, which `Get-PimManagerRole` now consults FIRST on a
  hosted deployment. Env vars still work and are checked next, so existing deployments are not
  stranded; this adds the auditable home rather than swapping one for another.

  🔒 SAME SAFETY RULES AS Set-PimPortalAdmins.ps1, for the same reason -- this is access control:
    * MERGE by default, keyed on identity. Adding one administrator must never silently revoke
      the others.
    * A read failure is FATAL, never "nothing was stored". On this table that difference is an
      access-control wipe.
    * Input is validated BEFORE the store is contacted, so bad input cannot half-write.
    * It reads back and compares. A write that is not verified is a hope.

  🔴 AND ONE RULE THIS SCRIPT HAS THAT THE OTHER DOES NOT: it refuses to leave the model with NO
  SuperAdmin. A store whose every entry is Reader locks every human out of the tool that manages
  privileged access -- recoverable only by editing the container, which is the thing this exists
  to stop needing.

.PARAMETER AccessJson
  Path to a JSON file, or the raw JSON: `{ "managerAccess": [ { "identity": "...", "role": "..." } ] }`
  role is one of Reader | Admin | SuperAdmin | Delegated.

.EXAMPLE
  pwsh -File Set-PimManagerAccess.ps1 -TenantId <t> -SqlServerFqdn sql-x.database.windows.net `
       -AdminAppId <appid> -AdminCertThumbprint <thumb> `
       -AccessJson '{"managerAccess":[{"identity":"a@x.io","role":"SuperAdmin"}]}' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$AdminAppId,
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    [Parameter(Mandatory)][string]$AccessJson,
    [switch]$Replace,
    [switch]$AllowNoSuperAdmin,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')

$VALID = @('Reader','Admin','SuperAdmin','Delegated')
$result = [ordered]@{ ok = $false; reason = ''; installed = @(); replaced = @(); removed = @(); whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Fail($m) { $result.reason = $m; Write-ResultFile; Write-Host "RESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM Manager RBAC -> pim.Settings['ManagerAccess'] ===" -ForegroundColor Cyan

# --- parse + validate FIRST -------------------------------------------------
$raw = $AccessJson
if (Test-Path -LiteralPath $AccessJson) { $raw = Get-Content -LiteralPath $AccessJson -Raw -Encoding UTF8 }
$incoming = @()
try {
    $p = $raw | ConvertFrom-Json
    $incoming = @(if ($p.PSObject.Properties['managerAccess']) { $p.managerAccess } else { $p })
} catch { Fail "input is not valid JSON: $($_.Exception.Message)" }
if (-not $incoming.Count) { Fail 'no entries in the input' }
foreach ($e in $incoming) {
    if (-not "$($e.identity)".Trim()) { Fail "an entry has no 'identity' -- it would match nobody" }
    if ("$($e.role)".Trim() -notin $VALID) {
        # A misspelled role must not silently become Reader here: the caller thinks they granted
        # something. Fail loudly at install time instead of at sign-in time.
        Fail "identity '$($e.identity)' has role '$($e.role)' -- must be one of: $($VALID -join ', ')"
    }
}
Note ("input: " + (($incoming | ForEach-Object { "$($_.identity)=$($_.role)" }) -join ', ')) 'DarkGray'

# --- connect ----------------------------------------------------------------
$global:PIM_TenantId    = $TenantId
$global:PIM_ClientId    = $AdminAppId
$global:PIM_SqlServer   = $SqlServerFqdn
$global:PIM_SqlDatabase = $SqlDatabase
if ("$AdminSecret".Trim())         { $global:PIM_ClientSecret   = $AdminSecret }
if ("$AdminCertThumbprint".Trim()) { $global:PIM_CertThumbprint = $AdminCertThumbprint }
if (-not "$AdminSecret".Trim() -and -not "$AdminCertThumbprint".Trim()) { Fail 'supply -AdminSecret or -AdminCertThumbprint' }
try { $cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $SqlDatabase }
catch { Fail "could not build a connection string: $($_.Exception.Message)" }

# --- read what is there (a read failure is FATAL) ---------------------------
$stored = @()
try {
    $cur = Get-PimSqlSetting -ConnectionString $cs -Name 'ManagerAccess'
    if ($cur) {
        if ($cur -is [string]) { $cur = $cur | ConvertFrom-Json }
        $stored = @(if ($cur.PSObject.Properties['managerAccess']) { $cur.managerAccess } else { $cur })
    }
} catch { Fail "could not read the existing ManagerAccess setting: $($_.Exception.Message)  (refusing to overwrite an unread access model)" }
Note ("already stored: " + $(if (@($stored).Count) { (@($stored) | ForEach-Object { "$($_.identity)=$($_.role)" }) -join ', ' } else { '(none -- roles currently come from env vars)' })) 'DarkGray'

# --- merge / replace --------------------------------------------------------
$byId = [ordered]@{}
if (-not $Replace) { foreach ($s in @($stored)) { $byId["$($s.identity)".ToLowerInvariant()] = $s } }
foreach ($i in $incoming) {
    $k = "$($i.identity)".ToLowerInvariant()
    if ($byId.Contains($k)) { $result.replaced += "$($i.identity)" } else { $result.installed += "$($i.identity)" }
    $byId[$k] = [ordered]@{ identity = "$($i.identity)".Trim(); role = "$($i.role)".Trim() }
}
if ($Replace) {
    $dropped = @(@($stored) | Where-Object { -not $byId.Contains("$($_.identity)".ToLowerInvariant()) } | ForEach-Object { "$($_.identity)" })
    $result.removed = $dropped
    if ($dropped.Count) { Note ("-Replace WILL REMOVE: " + ($dropped -join ', ')) 'Yellow' }
}
$final = @($byId.Values)

# 🔴 Never leave the model with no SuperAdmin.
$supers = @($final | Where-Object { "$($_.role)" -eq 'SuperAdmin' })
if (-not $supers.Count -and -not $AllowNoSuperAdmin) {
    Fail ("the resulting model has NO SuperAdmin -- that locks every human out of the tool that manages privileged access, " +
          "recoverable only by editing the container. Add one, or pass -AllowNoSuperAdmin if the env vars still carry one and you mean it.")
}
Note ("resulting model: $($final.Count) entr(y/ies), $($supers.Count) SuperAdmin") 'Gray'

if ($WhatIfPreference) { $result.ok = $true; $result.reason = 'what-if -- nothing written'; Write-ResultFile; Write-Host "RESULT: WHAT-IF -- nothing written" -ForegroundColor Yellow; exit 0 }

if ($PSCmdlet.ShouldProcess("pim.Settings['ManagerAccess']", "write $($final.Count) entr(y/ies)")) {
    Set-PimSqlSetting -ConnectionString $cs -Name 'ManagerAccess' -Value ([ordered]@{ managerAccess = $final })
}

# --- read back --------------------------------------------------------------
$verified = 0
try {
    $back = Get-PimSqlSetting -ConnectionString $cs -Name 'ManagerAccess'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    $verified = @(if ($back.PSObject.Properties['managerAccess']) { $back.managerAccess } else { $back }).Count
} catch { Fail "wrote, but could not read back: $($_.Exception.Message)" }
if ($verified -ne $final.Count) { Fail "read-back mismatch: wrote $($final.Count), store returned $verified" }

$result.ok = $true
$result.reason = "installed $($result.installed.Count), replaced $($result.replaced.Count), removed $($result.removed.Count); store now holds $verified"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
Write-Host "  NOTE: the Manager reads this at BOOT. Roll or restart the app for it to take effect." -ForegroundColor DarkGray
Write-Host "        SQL is consulted FIRST; PIM_SuperAdmins/PIM_Admins env vars still work and are" -ForegroundColor DarkGray
Write-Host "        checked next, so nothing is stranded mid-migration." -ForegroundColor DarkGray
exit 0
