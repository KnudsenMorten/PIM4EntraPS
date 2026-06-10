#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit: scan every Intune configuration policy that touches
    Chrome (or Edge) ExtensionInstallForcelist and print which extension
    ids each one ships. Used to pin down which Intune profile is pushing
    a malformed forcelist entry (empty string, wrong ext id, etc).

.DESCRIPTION
    Walks three Graph endpoints where forcelist values can live:
      - Settings Catalog (deviceManagement/configurationPolicies)
      - Administrative Templates / GP Configurations
            (deviceManagement/groupPolicyConfigurations + presentationValues)
      - Custom OMA-URI device configurations
            (deviceManagement/deviceConfigurations)

    For each policy, prints policy name + the raw forcelist value(s)
    found inside. Flags entries that look malformed:
      - empty string
      - missing ';<updateURL>' suffix
      - extension id not lowercase 32-char a..p

    No writes anywhere. Idempotent.

.PARAMETER TenantId
    Optional explicit tenant id. Default: interactive picker.

.EXAMPLE
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All'
    .\Audit-ChromeForcelistInIntune.ps1
#>
[CmdletBinding()]
param(
    [string]$TenantId
)

$ErrorActionPreference = 'Stop'

# --- Helpers ---------------------------------------------------------------

function Ensure-Graph {
    if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        $scopes = @('DeviceManagementConfiguration.Read.All')
        if ($TenantId) { Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome }
        else           { Connect-MgGraph -Scopes $scopes -NoWelcome }
        $ctx = Get-MgContext
    }
    Write-Host ("Connected: {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId) -ForegroundColor Cyan
    Write-Host ''
}

function Test-ForcelistEntry {
    param([string]$Entry)
    if ([string]::IsNullOrWhiteSpace($Entry)) { return 'EMPTY (malformed)' }
    $parts = $Entry -split ';', 2
    $id = $parts[0]
    if ($id -notmatch '^[a-p]{32}$') { return "INVALID-ID ($id)" }
    if ($parts.Count -lt 2 -or [string]::IsNullOrWhiteSpace($parts[1])) { return 'MISSING-URL' }
    return 'ok'
}

function Show-Hit {
    param([string]$PolicyName, [string]$Where, [array]$Entries)
    Write-Host ("  [{0}] {1}" -f $Where, $PolicyName) -ForegroundColor Yellow
    foreach ($e in $Entries) {
        $verdict = Test-ForcelistEntry -Entry $e
        $color = if ($verdict -eq 'ok') { 'Green' } else { 'Red' }
        Write-Host ("       -> '{0}'" -f $e) -ForegroundColor $color
        if ($verdict -ne 'ok') {
            Write-Host ("          $verdict") -ForegroundColor Red
        }
    }
}

# --- 1. Settings Catalog ----------------------------------------------------

function Audit-SettingsCatalog {
    Write-Host "=== Settings Catalog policies ===" -ForegroundColor Cyan
    $hits = 0
    $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
    $policies = @($resp.value)
    while ($resp.'@odata.nextLink') { $resp = Invoke-MgGraphRequest -Method GET -Uri $resp.'@odata.nextLink'; $policies += $resp.value }
    foreach ($p in $policies) {
        $settingsResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{0}/settings" -f $p.id)
        $settings = @($settingsResp.value)
        while ($settingsResp.'@odata.nextLink') { $settingsResp = Invoke-MgGraphRequest -Method GET -Uri $settingsResp.'@odata.nextLink'; $settings += $settingsResp.value }
        $entries = @()
        foreach ($s in $settings) {
            $json = ($s | ConvertTo-Json -Depth 30 -Compress)
            if ($json -match 'ExtensionInstallForcelist' -or $json -match 'extensioninstallforcelist') {
                # Walk the settingInstance tree looking for simpleSettingCollection value strings.
                $matches = [regex]::Matches($json, '"value"\s*:\s*"([^"]+)"')
                foreach ($m in $matches) {
                    $cand = $m.Groups[1].Value
                    if ($cand -match ';' -or [string]::IsNullOrWhiteSpace($cand) -or $cand -match '^[a-p]{0,32}$') {
                        $entries += $cand
                    }
                }
            }
        }
        if ($entries.Count -gt 0) {
            $hits++
            Show-Hit -PolicyName $p.name -Where 'SettingsCatalog' -Entries ($entries | Select-Object -Unique)
        }
    }
    if ($hits -eq 0) { Write-Host "  (no Settings Catalog policies touch ExtensionInstallForcelist)" -ForegroundColor DarkGray }
    Write-Host ''
}

# --- 2. Administrative Templates / GP Configurations ------------------------

function Audit-GroupPolicy {
    Write-Host "=== Administrative Templates (ADMX-backed) ===" -ForegroundColor Cyan
    $hits = 0
    $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
    $configs = @($resp.value)
    while ($resp.'@odata.nextLink') { $resp = Invoke-MgGraphRequest -Method GET -Uri $resp.'@odata.nextLink'; $configs += $resp.value }
    foreach ($c in $configs) {
        # Walk this config's definitionValues looking for ones whose definition is ExtensionInstallForcelist.
        $dvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition" -f $c.id)
        $dvs = @($dvResp.value)
        while ($dvResp.'@odata.nextLink') { $dvResp = Invoke-MgGraphRequest -Method GET -Uri $dvResp.'@odata.nextLink'; $dvs += $dvResp.value }
        foreach ($dv in $dvs) {
            $defName = $dv.definition.displayName
            if ($defName -notmatch 'ExtensionInstallForcelist' -and $defName -notmatch 'Configure the list of force-installed') { continue }
            $pvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues/{1}/presentationValues?`$expand=presentation" -f $c.id, $dv.id)
            $pvs = @($pvResp.value)
            $entries = @()
            foreach ($pv in $pvs) {
                if ($pv.values) { $entries += @($pv.values) }
                if ($pv.value -is [string])   { $entries += $pv.value }
                if ($pv.value -is [object[]]) { $entries += @($pv.value) }
            }
            if ($entries.Count -gt 0) {
                $hits++
                Show-Hit -PolicyName ("{0}  ({1})" -f $c.displayName, $defName) -Where 'AdminTemplate' -Entries ($entries | Select-Object -Unique)
            }
        }
    }
    if ($hits -eq 0) { Write-Host "  (no Administrative Templates touch ExtensionInstallForcelist)" -ForegroundColor DarkGray }
    Write-Host ''
}

# --- 3. Custom OMA-URI device configurations --------------------------------

function Audit-CustomDeviceConfig {
    Write-Host "=== Custom device configurations (OMA-URI etc) ===" -ForegroundColor Cyan
    $hits = 0
    $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations'
    $configs = @($resp.value)
    while ($resp.'@odata.nextLink') { $resp = Invoke-MgGraphRequest -Method GET -Uri $resp.'@odata.nextLink'; $configs += $resp.value }
    foreach ($c in $configs) {
        $json = ($c | ConvertTo-Json -Depth 25 -Compress -ErrorAction SilentlyContinue)
        if ($json -match 'ExtensionInstallForcelist' -or $json -match 'extensioninstallforcelist') {
            $matches = [regex]::Matches($json, '"value"\s*:\s*"([^"]+)"')
            $entries = @()
            foreach ($m in $matches) {
                $cand = $m.Groups[1].Value
                if ($cand -match ';' -or [string]::IsNullOrWhiteSpace($cand)) { $entries += $cand }
            }
            $hits++
            Show-Hit -PolicyName $c.displayName -Where 'CustomDeviceConfig' -Entries ($entries | Select-Object -Unique)
        }
    }
    if ($hits -eq 0) { Write-Host "  (no custom device configurations touch ExtensionInstallForcelist)" -ForegroundColor DarkGray }
    Write-Host ''
}

# --- Main ------------------------------------------------------------------

Ensure-Graph
Audit-SettingsCatalog
Audit-GroupPolicy
Audit-CustomDeviceConfig

Write-Host "Audit complete. Look for entries marked EMPTY (malformed) or INVALID-ID -- those are the source of the chrome://policy error." -ForegroundColor Cyan
