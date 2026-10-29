#Requires -Version 5.1

<#
.SYNOPSIS
    Applies a settings document (written by Export-PimSettings.ps1, or kept in source control) to a named PIM Manager
    environment's store: it shows the plan per setting (add / change / same), backs up what it would replace, and only
    with -Apply writes each setting and reads it back. A second -Apply changes nothing.

.DESCRIPTION
    Settings as code (REQUIREMENTS 77.13 REQ-NAMING-IAC and 72.4: "a supported, idempotent script surface that applies a
    settings document to a named environment, run deliberately by an operator (or a pipeline), with a plan/apply split
    and a read-back. Deliberately outside the downlink").

    WHAT THIS DELIBERATELY DOES NOT DO.
      * It never sets a secret or a setting that says who an environment is or who may act in it (who may use the
        Manager, approvers, break-glass accounts, demo mode, the environment name, licence / install keys, rings, the
        scenario, store / mail / Manager location, runtime state). A document that carries ONE such setting, or any
        value that looks like a secret, is REFUSED as a whole -- nothing is written. Inside a setting, the parts the
        export left out as secrets (redacted) keep the target's own value.
      * It never edits definitions, never moves a ring, never changes a credential, never deletes a setting: a setting
        the document does not name is left exactly as it is.
      * It never merges -- unless -MergeKeys asks for the one safe merge (the document's top-level keys win, keys only
        the target has are kept; objects only). An import otherwise REPLACES the setting's value.
      * It writes nothing without -Apply. A document from a newer format version is refused.
    Before anything is written the target's current value of every setting that would change is saved as a settings
    document in -BackupDir; importing that file restores it (a setting the import ADDED is listed in it, not removed).

.PARAMETER Path
    The settings document (.json) to apply.

.PARAMETER Name
    Apply only these settings of the document. Default: every setting in it.

.PARAMETER Server / -Database / -TenantId / -ClientId / -CertThumbprint
    The TARGET environment's store and the SPN (certificate) that may write it -- the same style as Copy-PimSettings.ps1.

.PARAMETER EnvironmentName
    The target environment's name as its Settings page shows it. When given, the import refuses a store whose
    environment name is different -- the guard against applying a baseline to the wrong environment.

.PARAMETER BackupDir
    Where the target's current values are written before anything changes. Default: <temp>\pim-settings-import.

.PARAMETER MergeKeys
    For an object setting: keep the top-level keys only the target has (the document's keys win). Arrays and plain
    values are still replaced whole.

.PARAMETER Apply
    Write. Without it the script only shows the plan (and still takes the backup in the temp folder).
    -WhatIf (with or without -Apply) shows the plan and the writes it would make; it writes nothing to the store.

.EXAMPLE
    # plan
    .\Import-PimSettings.ps1 -Path .\baseline\naming.json -EnvironmentName 'Contoso test' `
        -Server sql-b.database.windows.net -TenantId <b> -ClientId <b> -CertThumbprint <b>

.EXAMPLE
    # ...and for real
    .\Import-PimSettings.ps1 -Path .\baseline\naming.json ... -Apply

.LINK
    https://invardia.com/docs/pim/scripts/Import-PimSettings/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$Name,
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$CertThumbprint,
    [string]$EnvironmentName,
    [string]$BackupDir,
    [switch]$MergeKeys,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path      # ...\tools\setup
$sol  = Split-Path -Parent (Split-Path -Parent $here)        # ...\SOLUTIONS\PIM4EntraPS
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $sol 'engine\_shared\PIM-ConfigBackup.ps1')
. (Join-Path $here '_PimEnvironmentImport.ps1')
. (Join-Path $here '_PimSettingsCopy.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Import-PimSettings'
try {

# ---- 1. the document: every check BEFORE the store is touched -------------------------------------------------------
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "settings document not found: $Path" }
$raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
$chk = Test-PimSettingsDocument -Document $raw
if (-not $chk.ok) { throw "$Path -- $($chk.error)" }
$doc = $chk.document
foreach ($n in @($Name | Where-Object { "$_".Trim() })) {
    $why = Get-PimSettingTransferRefusal -Name $n
    if ($why) { throw ("REFUSING to import '$n': $why. A settings document never sets it.") }
}
$mine = Get-PimScriptVersion
try { if ("$($doc.productVersion)".Trim() -and [version]"$($doc.productVersion)" -gt [version]$mine) { Write-Warning ("the document was exported by PIM Manager $($doc.productVersion), this script is $mine -- a key this release does not know is written as it is.") } } catch { }

Write-Host ("Import settings: {0} -> {1} ({2}/{3})" -f $Path, $TenantId, $Server, $Database) -ForegroundColor Cyan
Write-Host ("  document : format {0}, exported {1} from {2} {3}" -f $doc.formatVersion, $doc.exportedUtc, $doc.source.tenantId, $(if ("$($doc.source.environmentName)") { "($($doc.source.environmentName))" } else { '' }))
if (-not $Apply) { Write-Host '  MODE     : PLAN (nothing is written -- re-run with -Apply)' -ForegroundColor Yellow }

# ---- 2. the target: the named environment ----------------------------------------------------------------------------
$cs = Use-PimSettingsStore -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertThumbprint -Server $Server -Database $Database
if ("$EnvironmentName".Trim()) {
    $have = ''
    try { $have = "$(Get-PimSqlSetting -ConnectionString $cs -Name 'EnvironmentName')".Trim() } catch { throw ("could not read the target's environment name: $($_.Exception.Message)") }
    if ($have -ne "$EnvironmentName".Trim()) {
        throw ("REFUSED: the store at $Server/$Database is environment '$have', not '$("$EnvironmentName".Trim())' -- nothing was written.")
    }
}

# ---- 3. the plan -------------------------------------------------------------------------------------------------------
$items = @(Get-PimSettingsImportItems -Document $doc -Names $Name -MergeKeys:$MergeKeys -Reader {
    param($n)
    try { , (Read-PimSettingValue -ConnectionString $cs -Name $n) } catch { throw ("could not read '$n' from the target: $($_.Exception.Message)") }
})
$missing = @($items | Where-Object { $_.state -eq 'missing' })
if ($missing.Count) { throw ("REFUSED: the document has no setting(s) " + (@($missing | ForEach-Object { $_.name }) -join ', ') + ' -- nothing was written.') }
foreach ($it in $items) {
    switch ($it.state) {
        'add'    { Write-Host ("  add     {0}" -f $it.name) -ForegroundColor Green }
        'change' { Write-Host ("  change  {0}  (key(s): {1})" -f $it.name, (@($it.changedKeys) -join ', ')) -ForegroundColor Yellow }
        default  { Write-Host ("  same    {0}" -f $it.name) -ForegroundColor DarkGray }
    }
    if (@($it.keptKeys).Count) { Write-Host ("          -MergeKeys: keeping the target's own key(s): {0}" -f (@($it.keptKeys) -join ', ')) -ForegroundColor Cyan }
}
$todo = @($items | Where-Object { $_.state -in @('add', 'change') })
$planLine = "Plan: {0} to add, {1} to change, {2} the same." -f @($items | Where-Object { $_.state -eq 'add' }).Count, @($items | Where-Object { $_.state -eq 'change' }).Count, @($items | Where-Object { $_.state -eq 'same' }).Count
Write-Host $planLine -ForegroundColor Cyan
if (-not $todo.Count) { Write-Host 'Nothing to do -- the environment already matches the document.' -ForegroundColor DarkGray; return }

# ---- 4. the backup of what would be replaced (a settings document: importing it restores those values) ----------------
$bk = Resolve-PimSettingsBackupDir -BackupDir $BackupDir -DefaultLeaf 'pim-settings-import' -DryRun ([bool]$WhatIfPreference)
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$before = [ordered]@{}; foreach ($it in @($todo | Where-Object { $_.state -eq 'change' })) { $before[$it.name] = $it.current }
$bdoc = New-PimSettingsDocument -Values $before -ProductVersion $mine -SourceTenantId $TenantId -SourceEnvironmentName "$EnvironmentName"
$bdoc['addedByImport'] = @($todo | Where-Object { $_.state -eq 'add' } | ForEach-Object { $_.name })
$backupFile = Join-Path $bk.dir ("TARGET-BEFORE-{0}.settings.json" -f $stamp)
Save-PimSettingsBackup -Path $backupFile -Value (ConvertTo-PimSettingJsonText -Value $bdoc -Indent 2) -Writes $bk.writes
if ($bk.writes) { Write-Host ("  target backup: {0}" -f $backupFile) }

if (-not $Apply) { Write-Host 'PLAN only -- re-run with -Apply to write.' -ForegroundColor Yellow; return }

# ---- 5. apply, one setting at a time, each read back ------------------------------------------------------------------
$changed = 0
foreach ($it in $todo) {
    if ($PSCmdlet.ShouldProcess("pim.Settings['$($it.name)'] in $Server/$Database (tenant $TenantId)", "$($it.state) from the settings document")) {
        Write-PimSettingWithReadBack -ConnectionString $cs -Name $it.name -Value $it.desired -BackupFile $backupFile
        Write-Host ("  {0} written and read back OK." -f $it.name) -ForegroundColor Green
        $changed++
    }
}
Write-Host ("`nDone. {0} setting(s) changed in {1}." -f $changed, $TenantId) -ForegroundColor Cyan
} finally { Stop-PimScriptRun -Script 'Import-PimSettings' }
