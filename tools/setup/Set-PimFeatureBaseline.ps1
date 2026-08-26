#Requires -Version 5.1
<#
.SYNOPSIS
  IMP-07 -- give a newly-deployed environment an EXPLICIT feature-gate baseline, so it is not inert.

.DESCRIPTION
  Operator directive 2026-08-12: *"the 3 mentioned blockers should be on and you have to make this a
  change for future deployments in estate + prod env"*.

  WHAT WENT WRONG WITHOUT THIS. `scheduler.jobs`, `alerting.email` and `msp.downlink` are all
  `tier='advanced', defaultEnabled=$false` in the shipped catalog, and nothing in onboarding turned
  them on. A fully-deployed environment therefore ticked on cadence and did NOTHING:

      delta-admins   ok=True   feature 'scheduler.jobs' disabled -- skipped

  ...every job, every 15 minutes, all day. Measured in EFIF, where the engine had never reconciled
  once since the environment was built.

  🪤 THE REASON NOBODY NOTICED, and the reason this script exists rather than a runbook note:
  **a gate-skip is recorded as `ok=True`.** The scheduler looks perfectly healthy -- `updatedUtc`
  advances, every job carries a fresh `lastRunUtc`/`nextRunUtc`, `JobRunHistory` is a wall of green
  rows -- and nothing anywhere states that the environment has never done any work. An inert
  environment is indistinguishable from a working one until someone asks why an account was not
  created. So the baseline has to be SET at deploy time and REPORTED, not left to a default.

  What each one being off actually costs:
    * scheduler.jobs  -- no reconcile, no provisioning, no discovery. The engine never runs.
    * alerting.email  -- PIM-Notify.ps1 L177 turns EVERY send into a no-op. TAP mail silently never
                         arrives while account creation still reports success. (This is the third
                         independent silent mail blocker found in one environment, alongside IMP-06
                         and IMP-06a.)
    * msp.downlink    -- the msp-pull job is disabled, which is acceptance control #1 itself.

.PARAMETER Gates
  Feature keys to turn ON. Defaults to the three above. Anything already persisted is MERGED, never
  dropped -- this script raises a floor, it does not impose a whole configuration, so an operator
  who deliberately enabled something extra does not lose it on the next deploy.

.PARAMETER Disable
  Feature keys to explicitly turn OFF. Use sparingly: an env that legitimately has no MSP
  relationship may want `msp.downlink` off rather than running a pull that finds nothing.

.NOTES
  The product catalog defaults are deliberately NOT changed. They are the conservative default for
  ~30 customer deployments that sync from main with no review step; flipping `defaultEnabled` would
  silently change behaviour for all of them at once. AutomateIT's OWN deployments (the estate and
  the production environment) opt in explicitly, here, and the choice is recorded in the store.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    # Identity used to reach the store. The onboarding SPN is the SQL server's Entra admin.
    [Parameter(Mandatory)][string]$AdminAppId,
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    [string[]]$Gates   = @('scheduler.jobs','alerting.email','msp.downlink'),
    [string[]]$Disable = @(),
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\SOLUTIONS\PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-FeatureCatalog.ps1')

$result = [ordered]@{ ok = $false; enabled = @(); disabled = @(); resolved = @{}; reason = '' }
function Note($m, $c = 'Gray') { Write-Host "    $m" -ForegroundColor $c }
function Write-ResultFile {
    if (-not "$OutFile".Trim()) { return }
    try {
        $d = Split-Path -Parent $OutFile
        if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
        ($result | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $OutFile -Encoding utf8 -WhatIf:$false
    } catch { Write-Warning "could not write -OutFile '$OutFile': $($_.Exception.Message)" }
}

Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " PIM FEATURE BASELINE (IMP-07)  $SqlServerFqdn/$SqlDatabase" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

# An EXPLICIT credential must beat ambient managed identity: mgmt1 has an MI of its own, and an MI
# can only mint tokens for ITS OWN tenant, so an ambient token authenticates successfully against
# the WRONG directory (BUG-34) and Azure SQL then reports it as a permissions problem.
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

# --- merge over what is already persisted ------------------------------------
$cur = @{}
try {
    $existing = Get-PimAllSqlSettings -ConnectionString $cs
    if ($existing -and $existing.ContainsKey('FeatureGates')) {
        $raw = $existing['FeatureGates']
        if ($raw -is [string]) { $raw = $raw | ConvertFrom-Json }
        if ($raw -and $raw.gates) {
            foreach ($p in $raw.gates.PSObject.Properties) { $cur["$($p.Name)"] = [bool]$p.Value }
        }
    }
} catch {
    # A read failure must NOT be treated as "nothing persisted" -- that would silently discard an
    # operator's existing choices on the next deploy. Same class as ESTATE-14.
    $result.reason = "could not read existing FeatureGates: $($_.Exception.Message)"
    Write-ResultFile; Write-Host "RESULT: FAILED -- $($result.reason)  (refusing to overwrite an unread gate map)" -ForegroundColor Red; exit 1
}
Note ("already persisted: " + $(if ($cur.Count) { ($cur.Keys | Sort-Object) -join ', ' } else { '(none -- all advanced features at shipped default OFF)' })) 'DarkGray'

foreach ($k in $Gates)   { if (-not (Get-PimFeatureCatalogEntry -Key $k)) { throw "unknown feature key '$k' -- not in the catalog" }; $cur[$k] = $true }
foreach ($k in $Disable) { if (-not (Get-PimFeatureCatalogEntry -Key $k)) { throw "unknown feature key '$k' -- not in the catalog" }; $cur[$k] = $false }
$result.enabled  = @($Gates)
$result.disabled = @($Disable)

Write-Host ""
foreach ($e in ($cur.GetEnumerator() | Sort-Object Key)) {
    Write-Host ("    {0,-22} {1}" -f $e.Key, $(if ($e.Value) { 'ON' } else { 'off' })) -ForegroundColor $(if ($e.Value) { 'Green' } else { 'DarkGray' })
}
if (-not $PSCmdlet.ShouldProcess("$SqlServerFqdn/$SqlDatabase", 'persist FeatureGates')) {
    $result.ok = $true; $result.reason = 'whatif'; Write-ResultFile; exit 0
}

Set-PimSqlSetting -ConnectionString $cs -Name 'FeatureGates' -Value ([ordered]@{ gates = $cur })

# --- verify through the resolver the ENGINE uses ------------------------------
# Not a raw re-read: the point is to prove what a gate check will actually see. A control key that
# was NOT requested is asserted to stay OFF, so a resolver that simply answered $true to everything
# could not pass this.
$back = Get-PimAllSqlSettings -ConnectionString $cs
$global:PIM_NamingConventions = @{}
foreach ($k in @($back.Keys)) { $global:PIM_NamingConventions[$k] = $back[$k] }

$bad = @()
foreach ($k in $Gates)   { $on = Test-PimFeatureEnabled -Key $k; $result.resolved[$k] = [bool]$on; if (-not $on) { $bad += "$k should be ON" } }
foreach ($k in $Disable) { $on = Test-PimFeatureEnabled -Key $k; $result.resolved[$k] = [bool]$on; if ($on)      { $bad += "$k should be off" } }
$control = 'discovery.sweep'
if (($Gates -notcontains $control) -and ($Disable -notcontains $control)) {
    if (Test-PimFeatureEnabled -Key $control) { $bad += "control key '$control' resolved ON without being requested -- the gate resolver is not discriminating" }
}
if ($bad.Count) {
    $result.reason = ($bad -join '; ')
    Write-ResultFile
    Write-Host "`nRESULT: FAILED -- persisted but not correctly resolved: $($result.reason)" -ForegroundColor Red
    exit 1
}

$result.ok = $true
Write-Host ""
Write-Host "  VERIFIED via Test-PimFeatureEnabled: $(($Gates) -join ', ') ON$(if ($Disable.Count) { "; $(($Disable) -join ', ') off" })" -ForegroundColor Green
Write-Host "  (control key '$control' left off, proving the resolver discriminates)" -ForegroundColor DarkGray
Write-ResultFile
exit 0
