#Requires -Version 5.1

<#
.SYNOPSIS
    Exports PIM Manager settings (for example the naming conventions) from one environment's store to a settings document
    (a JSON file) that Import-PimSettings.ps1 applies to another environment: settings as code, never secrets, never
    identity or access settings.

.DESCRIPTION
    Settings as code (REQUIREMENTS 77.13 REQ-NAMING-IAC and 72.4, operator: "i need to be able to export / import naming
    conventions using the scripts for IaC purpose to baseline a tenant" / "We need a way to set settings using scripts
    (IaC)"). The file can be kept in source control, reviewed, and applied deliberately with Import-PimSettings.ps1.

    THE DOCUMENT: { format = 'pim-manager-settings'; formatVersion = 1; productVersion; exportedUtc;
    source = { tenantId; environmentName }; settings = { <Name> = <value> }; redacted = { <Name> = [paths] }; skipped = [...] }.
    Each setting is the whole stored value (an import replaces the value, so the document carries every key).

    WHAT THIS NEVER EXPORTS. A secret, or a setting that says who this environment is or who may act in it: who may use
    the Manager, approvers, break-glass accounts, demo mode, the environment name, the licence and install keys, rings,
    the scenario, the store / mail / Manager location, runtime state -- the never-copy list of Copy-PimSettings, the
    configuration backup's deny list and the environment import's list, all three. A -Name on that list is REFUSED.
    Without -Name (-All) such settings are left out and listed under skipped. Inside a kept setting every property that
    looks like a secret (by name or by value) is removed and its path is listed under redacted; an import keeps the
    target's own value there.

    Reads only. The file is written only when it is outside -WhatIf; an existing file is replaced only with -Force.

.PARAMETER Name
    The setting(s) to export, e.g. NamingConventions. Use -All instead to export every setting that may be exported.

.PARAMETER All
    Export every setting in the store except the ones that are never exported (they are listed as skipped).

.PARAMETER Path
    The settings document to write (a .json file).

.PARAMETER Server / -Database / -TenantId / -ClientId / -CertThumbprint
    The environment's store and the SPN (certificate) that may read it -- the same style as Copy-PimSettings.ps1.

.PARAMETER Force
    Replace -Path when it already exists.

.EXAMPLE
    .\Export-PimSettings.ps1 -Name NamingConventions -Path .\baseline\naming.json `
        -Server sql-a.database.windows.net -TenantId <a> -ClientId <a> -CertThumbprint <a>

.EXAMPLE
    .\Export-PimSettings.ps1 -All -Path .\baseline\settings.json -Server sql-a.database.windows.net -TenantId <a> -ClientId <a> -CertThumbprint <a>

.LINK
    https://invardia.com/docs/pim/scripts/Export-PimSettings/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Name,
    [switch]$All,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$CertThumbprint,
    [switch]$Force
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
$null = Start-PimScriptRun -Script 'Export-PimSettings'
try {

$want = @($Name | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
if ($All -and $want.Count) { throw 'Give -Name or -All, not both.' }
if (-not $All -and -not $want.Count) { throw 'Give the setting(s) to export with -Name (e.g. -Name NamingConventions), or -All for every setting that may be exported.' }
# A named setting that may never be exported is refused BEFORE the store is read.
foreach ($n in $want) {
    $why = Get-PimSettingTransferRefusal -Name $n
    if ($why) { throw ("REFUSING to export '$n': $why. A settings document never carries it.") }
}
if ((Test-Path -LiteralPath $Path) -and -not $Force) { throw "$Path already exists -- give -Force to replace it." }

Write-Host ("Export settings from {0} ({1}/{2})" -f $TenantId, $Server, $Database) -ForegroundColor Cyan
$cs = Use-PimSettingsStore -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertThumbprint -Server $Server -Database $Database
$names = if ($All) { @(Get-PimStoreSettingNames -ConnectionString $cs) } else { $want }
$values = [ordered]@{}
foreach ($n in $names) {
    $v = $null
    # a setting that is never exported is not even read (its value -- a secret, a key -- never enters this process);
    # New-PimSettingsDocument lists it as skipped with the reason
    if (Get-PimSettingTransferRefusal -Name $n) { $values[$n] = $null; continue }
    try { $v = Read-PimSettingValue -ConnectionString $cs -Name $n } catch { throw ("could not read '$n': $($_.Exception.Message)") }
    if ($null -eq $v -and -not $All) { throw ("'$n' is not set in this store -- nothing to export (nothing was written).") }
    $values[$n] = $v
}
$envName = ''
try { $envName = "$(Get-PimSqlSetting -ConnectionString $cs -Name 'EnvironmentName')".Trim() } catch { $envName = '' }

$doc = New-PimSettingsDocument -Values $values -ProductVersion (Get-PimScriptVersion) -SourceTenantId $TenantId -SourceEnvironmentName $envName -Strict:(-not $All)
foreach ($k in @($doc.settings.Keys)) {
    $r = if ($doc.redacted.Contains($k)) { " (secret part(s) left out: $(@($doc.redacted[$k]) -join ', '))" } else { '' }
    Write-Host ("  export  {0}{1}" -f $k, $r) -ForegroundColor Green
}
foreach ($s in @($doc.skipped)) { Write-Host ("  skipped {0} -- {1}" -f $s.name, $s.reason) -ForegroundColor DarkGray }
if (-not @($doc.settings.Keys).Count) { throw 'nothing to export: every setting asked for is one a settings document never carries (nothing was written).' }

$json = ConvertTo-PimSettingJsonText -Value $doc -Indent 2   # never ConvertTo-Json: on 5.1 it writes a pipeline-wrapped array as {"value":[...],"Count":n}
if ($PSCmdlet.ShouldProcess($Path, "write the settings document ($(@($doc.settings.Keys).Count) setting(s))")) {
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    Write-Host ("`nDone. {0} setting(s) written to {1}." -f @($doc.settings.Keys).Count, $Path) -ForegroundColor Cyan
}
} finally { Stop-PimScriptRun -Script 'Export-PimSettings' }
