#Requires -Version 5.1
<#
.SYNOPSIS
    Drill into the two Intune policies that the first audit flagged as
    touching ExtensionInstallForcelist and dump the raw list values verbatim
    so we can see hidden blank entries / phantom rows.

.DESCRIPTION
    First audit (Audit-ChromeForcelistInIntune.ps1) confirmed the source is
    one of these two:
      - Settings Catalog: 'Browser Extensions Silently Installed (Google Chrome + Edge)'
      - Administrative Templates: '[PimActivator] client settings'

    Both write to the same HKLM forcelist. chrome://policy shows the merged
    result with a blank string at index 1 + a conflict with a different
    extension id. This script prints each policy's raw forcelist values
    (one per line, with index + length), so we can see which one has the
    phantom blank.

    Read-only. No writes.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Graph. Run Connect-MgGraph first." }
Write-Host ("Connected: {0}  (tenant {1})" -f $ctx.Account, $ctx.TenantId) -ForegroundColor Cyan
Write-Host ''

function Show-Entries {
    param([string]$Label, [array]$Entries)
    Write-Host ("--- {0} ({1} value(s)) ---" -f $Label, $Entries.Count) -ForegroundColor Yellow
    for ($i=0; $i -lt $Entries.Count; $i++) {
        $e = $Entries[$i]
        if ($null -eq $e) { $e = '' }
        $len = ([string]$e).Length
        $flag = ''
        if ([string]::IsNullOrWhiteSpace($e)) { $flag = '   <<< BLANK (this would cause the chrome://policy error)' }
        Write-Host ("  [{0}] (len={1}) '{2}'{3}" -f $i, $len, $e, $flag) -ForegroundColor $(if ($flag) {'Red'} else {'Green'})
    }
    Write-Host ''
}

# -------------------------------------------------------------------------
# 1. Settings Catalog: 'Browser Extensions Silently Installed (Google Chrome + Edge)'
# -------------------------------------------------------------------------
Write-Host "=== Settings Catalog policies that touch ExtensionInstallForcelist ===" -ForegroundColor Cyan
$cpResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies'
$policies = @($cpResp.value)
while ($cpResp.'@odata.nextLink') { $cpResp = Invoke-MgGraphRequest -Method GET -Uri $cpResp.'@odata.nextLink'; $policies += $cpResp.value }

foreach ($p in $policies) {
    $sResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{0}/settings" -f $p.id)
    $settings = @($sResp.value)
    while ($sResp.'@odata.nextLink') { $sResp = Invoke-MgGraphRequest -Method GET -Uri $sResp.'@odata.nextLink'; $settings += $sResp.value }

    foreach ($s in $settings) {
        $json = ($s | ConvertTo-Json -Depth 30 -Compress)
        if ($json -notmatch 'ExtensionInstallForcelist' -and $json -notmatch 'extensioninstallforcelist') { continue }
        Write-Host ("Policy: {0}" -f $p.name) -ForegroundColor Cyan
        Write-Host ("Setting id: {0}" -f $s.id) -ForegroundColor DarkGray

        # Walk the settingInstance tree to find every simpleSettingCollection / simpleSetting and dump its value(s)
        $vals = @()
        function Walk-Node {
            param($node)
            if ($null -eq $node) { return }
            if ($node -is [System.Collections.IDictionary]) {
                # simpleSettingCollectionValue -> array of {value:'...'}
                if ($node.ContainsKey('simpleSettingCollectionValue')) {
                    foreach ($child in @($node['simpleSettingCollectionValue'])) {
                        if ($child -is [System.Collections.IDictionary] -and $child.ContainsKey('value')) {
                            $script:vals += [string]$child['value']
                        }
                    }
                }
                if ($node.ContainsKey('value') -and $node['value'] -is [string]) {
                    # single simpleSettingInstance.value (rare for forcelist; harmless to include)
                    if (-not $node.ContainsKey('simpleSettingCollectionValue')) {
                        $script:vals += [string]$node['value']
                    }
                }
                foreach ($k in $node.Keys) {
                    if ($node[$k] -is [System.Collections.IDictionary] -or $node[$k] -is [System.Collections.IEnumerable]) {
                        Walk-Node $node[$k]
                    }
                }
            } elseif ($node -is [System.Collections.IEnumerable] -and -not ($node -is [string])) {
                foreach ($item in $node) { Walk-Node $item }
            }
        }
        Walk-Node $s
        Show-Entries -Label ("SettingsCatalog: {0}" -f $p.name) -Entries $vals
    }
}

# -------------------------------------------------------------------------
# 2. ADMX: '[PimActivator] client settings'
# -------------------------------------------------------------------------
Write-Host "=== ADMX (groupPolicyConfigurations) that touch ExtensionInstallForcelist ===" -ForegroundColor Cyan
$gpResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
$configs = @($gpResp.value)
while ($gpResp.'@odata.nextLink') { $gpResp = Invoke-MgGraphRequest -Method GET -Uri $gpResp.'@odata.nextLink'; $configs += $gpResp.value }

foreach ($c in $configs) {
    $dvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition" -f $c.id)
    $dvs = @($dvResp.value)
    while ($dvResp.'@odata.nextLink') { $dvResp = Invoke-MgGraphRequest -Method GET -Uri $dvResp.'@odata.nextLink'; $dvs += $dvResp.value }

    foreach ($dv in $dvs) {
        $defName = $dv.definition.displayName
        if ($defName -notmatch 'ExtensionInstallForcelist' -and $defName -notmatch 'Configure the list of force-installed') { continue }
        Write-Host ("Policy: {0}  ({1})" -f $c.displayName, $defName) -ForegroundColor Cyan

        $pvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues/{1}/presentationValues?`$expand=presentation" -f $c.id, $dv.id)
        $pvs = @($pvResp.value)
        $entries = @()
        foreach ($pv in $pvs) {
            # ADMX list-box values arrive as @{values=@(@{name='1';value='...'}, @{name='2';value='...'}, ...)}
            if ($pv.values) {
                foreach ($v in @($pv.values)) {
                    if ($v -is [System.Collections.IDictionary]) {
                        if ($v.ContainsKey('value')) { $entries += [string]$v['value'] }
                        elseif ($v.ContainsKey('name')) { $entries += [string]$v['name'] }
                    } else {
                        $entries += [string]$v
                    }
                }
            } elseif ($pv.value) {
                if ($pv.value -is [array]) { $entries += @($pv.value) | ForEach-Object { [string]$_ } }
                else                       { $entries += [string]$pv.value }
            } else {
                # Last resort: dump the whole presentationValue as JSON for inspection
                Write-Host ("  raw presentationValue JSON: " + (($pv | ConvertTo-Json -Depth 10 -Compress))) -ForegroundColor DarkGray
            }
        }
        Show-Entries -Label ("ADMX: {0}" -f $c.displayName) -Entries $entries
    }
}

Write-Host "Done. Any [N] with BLANK above is the source of chrome://policy's 'Invalid extension ID' error." -ForegroundColor Cyan
