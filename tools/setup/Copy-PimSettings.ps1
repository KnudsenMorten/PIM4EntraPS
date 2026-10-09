#Requires -Version 5.1

<#
.SYNOPSIS
    Copies named PIM Manager settings (for example the naming conventions) from one environment's store to another
    environment's store: it reads both, shows the difference, backs up the target's current value, and only with
    -Apply overwrites it and reads it back.

.DESCRIPTION
    Export settings from one PIM tenant and import them into another (operator, 2026-09-22:
    "make info on the settings on how to export/import between tenants (script)").

    Settings live in `pim.Settings` as one JSON document per name (naming conventions, schedules,
    manager access, ...). Copying one between tenants -- a managing tenant's naming conventions to a managed
    tenant, a known-good schedule to a new environment -- was a hand-written SQL job every time, and
    a hand-written job is where the wrong tenant gets written.

    🔒 WHAT THIS DELIBERATELY DOES NOT DO.
      * It never copies a setting that names the tenant it came from: ManagerAccess, the SQL/store
        pointers, the MSP registry, the emergency passphrase, the downlink trust pins. Those are the
        environment's own identity, and carrying them across is how a tenant ends up trusting
        another tenant's administrators. The block list is in $script:PimSettingsNeverCopy and a
        -Name that hits it is REFUSED, not warned about.
      * It never merges -- unless -MergeKeys asks for the one safe merge (below). A setting is one
        document; a half-merged document is a shape no reader expects. The target's current value is
        written to a backup file FIRST, and restoring it is the same command with -From/-To swapped.
      * It writes nothing without -Apply. The default is a diff.

.PARAMETER Name
    The setting(s) to copy, e.g. NamingConventions. Required -- there is no "copy everything".

.PARAMETER FromServer / -FromDatabase / -FromTenantId / -FromClientId / -FromCertThumbprint
    The SOURCE tenant's store and the SPN (certificate) that may read it.

.PARAMETER ToServer / -ToDatabase / -ToTenantId / -ToClientId / -ToCertThumbprint
    The TARGET tenant's store and the SPN that may write it.

.PARAMETER BackupDir
    Where the target's current value is written before anything changes. Default: the user's temp.

.PARAMETER MergeKeys
    (2026-10-03) For an OBJECT setting: the source's top-level keys win and the keys ONLY the target has are KEPT --
    so copying from an environment set up on an older release does not drop the keys a newer release added (found
    copying NamingConventions to the rebuilt ring-1 environment). Arrays and plain values are still replaced whole.
    The kept keys are listed before anything is written.

.PARAMETER Apply
    Write. Without it the script only reports what WOULD change (and still takes the backup).
    -WhatIf (with or without -Apply) reads both stores, shows the difference and prints the overwrite it would make;
    it writes nothing to either store, and a backup outside the temp folder is only announced.

.EXAMPLE
    # managing tenant -> managed tenant, naming conventions, dry run
    .\Copy-PimSettings.ps1 -Name NamingConventions `
        -FromServer sql-a.database.windows.net -FromTenantId <a> -FromClientId <a> -FromCertThumbprint <a> `
        -ToServer   sql-b.database.windows.net -ToTenantId   <b> -ToClientId   <b> -ToCertThumbprint   <b>

.EXAMPLE
    # ...and for real
    .\Copy-PimSettings.ps1 -Name NamingConventions ... -Apply

.LINK
    https://invardia.com/docs/pim/scripts/Copy-PimSettings/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$Name,
    [Parameter(Mandatory)][string]$FromServer,
    [string]$FromDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$FromTenantId,
    [Parameter(Mandatory)][string]$FromClientId,
    [Parameter(Mandatory)][string]$FromCertThumbprint,
    [Parameter(Mandatory)][string]$ToServer,
    [string]$ToDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$ToTenantId,
    [Parameter(Mandatory)][string]$ToClientId,
    [Parameter(Mandatory)][string]$ToCertThumbprint,
    [string]$BackupDir,
    [switch]$MergeKeys,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path      # ...\tools\setup
$sol  = Split-Path -Parent (Split-Path -Parent $here)        # ...\SOLUTIONS\PIM4EntraPS
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $here '_PimSettingsCopy.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Copy-PimSettings'
try {

# 🔒 Settings that describe WHO this environment is, or WHO may act in it. Copying one of these
# between tenants does not configure the target -- it points the target at the source's identities.
$script:PimSettingsNeverCopy = @(
    'ManagerAccess',            # who may use the Manager here
    'PortalAdmins',
    'EmergencyOverride',        # break-glass state
    'EmergencyPassphrase',
    'DownlinkTrust',            # which master signing keys this tenant trusts
    'BaselineTrustedKeys',
    'MspRegistry', 'MspTenants', 'CentralAdmins',
    'SqlStore', 'StorePointer', 'Instances',
    'Licence', 'License',
    'EnvironmentName',          # this environment's own display name (operator 2026-10-04) -- names THIS one
    'DemoMode', 'DemoGuestGroup' # s98: who may act here (a live demo); carried elsewhere it would cap that tenant's people
)

function Confirm-Copyable {
    param([string]$SettingName)
    foreach ($b in $script:PimSettingsNeverCopy) {
        if ("$SettingName".Trim() -ieq $b) {
            throw ("REFUSING to copy '$SettingName': it names the tenant it came from (identities, trust pins or " +
                   "store pointers). Copying it would point '$ToTenantId' at '$FromTenantId'. Set it in the target " +
                   'tenant on its own, with the tool that owns it.')
        }
    }
}

function Use-Tenant {
    param([string]$TenantId, [string]$ClientId, [string]$Thumbprint, [string]$Server, [string]$Database)
    $global:PIM_TenantId          = $TenantId
    $global:PIM_SqlClientId       = $ClientId
    $global:PIM_SqlCertThumbprint = $Thumbprint
    return (Get-PimSqlConnectionString -Server $Server -Database $Database)
}

if (-not "$BackupDir".Trim()) { $BackupDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-settings-copy' }
# 12.7: -WhatIf writes nothing outside the temp folder. A backup in the temp folder (the default) is still taken -- it is
# what makes the dry run's diff restorable -- and a backup anywhere else is only announced.
$backupInTemp = ([IO.Path]::GetFullPath($BackupDir)).StartsWith(([IO.Path]::GetFullPath([IO.Path]::GetTempPath())), [StringComparison]::OrdinalIgnoreCase)
$backupWrites = $backupInTemp -or -not $WhatIfPreference
function Save-Backup {
    param([string]$Path, [string]$Value)
    if (-not $backupWrites) { Write-Host "  What if: would write the backup $Path" -ForegroundColor Yellow; return }
    Set-Content -Path $Path -Value $Value -Encoding UTF8 -WhatIf:$false -Confirm:$false
}
if ($backupWrites -and -not (Test-Path -LiteralPath $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir -WhatIf:$false -Confirm:$false | Out-Null }
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')

foreach ($n in @($Name)) { Confirm-Copyable -SettingName $n }

Write-Host ("Copy settings: {0} -> {1}" -f $FromTenantId, $ToTenantId) -ForegroundColor Cyan
Write-Host ("  settings : {0}" -f ($Name -join ', '))
Write-Host ("  backups  : {0}" -f $BackupDir)
if (-not $Apply) { Write-Host '  MODE     : dry run (nothing is written)' -ForegroundColor Yellow }

$changed = 0
foreach ($n in @($Name)) {
    Write-Host ("`n== {0} ==" -f $n) -ForegroundColor Cyan
    $csFrom = Use-Tenant -TenantId $FromTenantId -ClientId $FromClientId -Thumbprint $FromCertThumbprint -Server $FromServer -Database $FromDatabase
    $src = $null
    try { $src = Get-PimSqlSetting -ConnectionString $csFrom -Name $n } catch { throw ("could not read '$n' from the source: $($_.Exception.Message)") }
    if ($null -eq $src) { Write-Host "  the SOURCE has no such setting -- skipped (nothing is cleared in the target)" -ForegroundColor Yellow; continue }
    Save-Backup -Path (Join-Path $BackupDir ("{0}-SOURCE-{1}.json" -f $n, $stamp)) -Value ($src | ConvertTo-Json -Depth 12)

    $csTo = Use-Tenant -TenantId $ToTenantId -ClientId $ToClientId -Thumbprint $ToCertThumbprint -Server $ToServer -Database $ToDatabase
    $dst = $null
    try { $dst = Get-PimSqlSetting -ConnectionString $csTo -Name $n } catch { throw ("could not read '$n' from the target: $($_.Exception.Message)") }
    $dstJson = $(if ($null -ne $dst) { ($dst | ConvertTo-Json -Depth 12) } else { '' })
    # -MergeKeys: the value to write is the source with the target's EXTRA top-level keys kept (objects only).
    if ($MergeKeys) {
        $kept = @(Get-PimSettingKeyDiff -Target $dst -Source $src)
        if ($kept.Count) { Write-Host ("  -MergeKeys: keeping the target's own key(s): {0}" -f ($kept -join ', ')) -ForegroundColor Cyan }
        $src = Merge-PimSettingKeys -Target $dst -Source $src
    }
    $srcJson = ($src | ConvertTo-Json -Depth 12)
    # 🔑 The target's CURRENT value is saved before anything is written, every run -- including a dry
    # run. Restoring is this same script with -From/-To swapped, or an import of this file.
    $backupFile = Join-Path $BackupDir ("{0}-TARGET-BEFORE-{1}.json" -f $n, $stamp)
    Save-Backup -Path $backupFile -Value $dstJson
    if ($backupWrites) { Write-Host ("  target backup: {0}" -f $backupFile) }

    if (($srcJson -replace '\s', '') -eq ($dstJson -replace '\s', '')) {
        Write-Host '  identical already -- nothing to do.' -ForegroundColor DarkGray
        continue
    }
    Write-Host '  SOURCE:' -ForegroundColor Green; Write-Host ('    ' + ($srcJson -replace "`r?`n", "`n    "))
    Write-Host '  TARGET (now):' -ForegroundColor Yellow; Write-Host ('    ' + ($(if ($dstJson) { $dstJson } else { '(not set)' }) -replace "`r?`n", "`n    "))

    if (-not $Apply) { Write-Host '  would be overwritten with SOURCE (re-run with -Apply)' -ForegroundColor Yellow; continue }
    if ($PSCmdlet.ShouldProcess("pim.Settings['$n'] in $ToServer/$ToDatabase (tenant $ToTenantId)", 'overwrite with the source value')) {
        Set-PimSqlSetting -ConnectionString $csTo -Name $n -Value $src
        $after = Get-PimSqlSetting -ConnectionString $csTo -Name $n
        $afterJson = $(if ($null -ne $after) { ($after | ConvertTo-Json -Depth 12) } else { '' })
        if (($afterJson -replace '\s', '') -ne ($srcJson -replace '\s', '')) {
            throw ("read-back of '$n' does not match what was written -- the target may hold a partial value. " +
                   "Restore from $backupFile before continuing.")
        }
        Write-Host '  written and read back OK.' -ForegroundColor Green
        $changed++
    }
}

Write-Host ("`nDone. {0} setting(s) changed in {1}." -f $changed, $ToTenantId) -ForegroundColor Cyan
if (-not $Apply) { Write-Host 'Dry run -- re-run with -Apply to write.' -ForegroundColor Yellow }
} finally { Stop-PimScriptRun -Script 'Copy-PimSettings' }
