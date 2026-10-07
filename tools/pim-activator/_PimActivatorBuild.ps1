#Requires -Version 5.1
<#
  97.2 -- the builder behind Operations > PIM Activator in the PIM Manager (operator 2026-10-07: "Easy Setup of Intune
  (remediation jobs) ... Edge for Business ... the entra apps ... PROD and TEST ... build of the catalog ... scripts for
  servers ... make it optional to which group or all devices or all users"). PURE: no network, no Graph -- the Manager
  calls it with what it knows, and the offline suite (tests\Test-PimActivatorBuild.ps1) proves it.

  What it builds:
    * the Intune Remediation pair (Detect / Remediate) with the SETTINGS block filled in -- channel, browsers, the tenant
      catalog, the two limits -- identically in both files (the README's rule), from the shipped scripts;
    * the Edge management service ExtensionSettings JSON ("Import JSON" on the Managed extensions tab) for the chosen
      channels, and the ExtensionInstallSources value;
    * the tenant catalog defaults from this environment (tenant id, the Activator app id, defaults);
    * the exact commands: the apps (PROD + TEST), the Remediation upload (group / all devices / all users), the
      server / no-Intune install.
#>

$script:PimActivatorChannels = [ordered]@{
    Released = [ordered]@{ id = 'eheocihmlppcophaeakmdenhgcookkab'; updateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'; label = 'PROD'; appName = 'PIM Activator' }
    Test     = [ordered]@{ id = 'glldnbmjpdkjemcnficagdhgienfdpoo'; updateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates-test.xml'; label = 'TEST'; appName = 'PIM Activator (TEST)' }
}
$script:PimActivatorMinimumVersion = '1.6.126'
$script:PimActivatorInstallSource = 'https://knudsenmorten.github.io/*'

function Get-PimActivatorChannel {
    <# PURE. Released | Test -> @{ id; updateUrl; label; appName }. Throws on anything else. #>
    param([Parameter(Mandatory)][string]$Channel)
    foreach ($k in $script:PimActivatorChannels.Keys) { if ($k -ieq "$Channel".Trim()) { return $script:PimActivatorChannels[$k] } }
    throw "Unknown PIM Activator channel '$Channel' (Released or Test)."
}

function Get-PimActivatorEdgePolicy {
    <#
      PURE. The Edge management service settings for the chosen channels: @{ installSources; extensionSettingsJson;
      minimumVersion }. One policy per AUDIENCE (README): test users get both channels, everyone else Released only.
    #>
    param([string[]]$Channels = @('Released'))
    $obj = [ordered]@{}
    foreach ($c in @($Channels | Where-Object { $_ } | Select-Object -Unique)) {
        $ch = Get-PimActivatorChannel -Channel $c
        $obj[$ch.id] = [ordered]@{ installation_mode = 'force_installed'; update_url = $ch.updateUrl; override_update_url = $true; minimum_version_required = $script:PimActivatorMinimumVersion }
    }
    return [ordered]@{ installSources = $script:PimActivatorInstallSource; minimumVersion = $script:PimActivatorMinimumVersion
                       extensionSettingsJson = ($obj | ConvertTo-Json -Depth 5) }
}

function New-PimActivatorCatalog {
    <#
      PURE. The tenant catalog (the JSON the extension reads) for THIS environment. -ClientId = the Activator app of the
      channel. Optional prefixes narrow what the popup lists. Returns the JSON text (an array of one tenant).
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId,
          [string]$DefaultJustification = 'Change in infrastructure', [int]$DefaultDurationHours = 8,
          [string]$Prefix = '', [string]$EntraPrefix = '', [string]$AzurePrefix = '')
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ("$TenantId" -notmatch $guid) { throw "TenantId is not a GUID: '$TenantId'" }
    if ("$ClientId" -notmatch $guid) { throw "ClientId (the PIM Activator app) is not a GUID: '$ClientId'" }
    if ($DefaultDurationHours -lt 1 -or $DefaultDurationHours -gt 24) { throw 'DefaultDurationHours must be 1-24.' }
    $t = [ordered]@{ name = "$Name".Trim(); tenantId = "$TenantId".ToLowerInvariant(); clientId = "$ClientId".ToLowerInvariant()
                     defaultJustification = "$DefaultJustification"; defaultDurationHours = $DefaultDurationHours }
    if ("$Prefix".Trim())      { $t['prefix'] = "$Prefix".Trim() }
    if ("$EntraPrefix".Trim()) { $t['entraPrefix'] = "$EntraPrefix".Trim() }
    if ("$AzurePrefix".Trim()) { $t['azurePrefix'] = "$AzurePrefix".Trim() }
    return (ConvertTo-Json -InputObject @($t) -Depth 4)
}

function Set-PimActivatorRemediationSettings {
    <#
      PURE. The shipped Detect / Remediate script text with its SETTINGS block filled in. Only these five assignments are
      replaced; everything else stays byte-for-byte. Throws when a setting line is not found (a changed script must not
      ship with a half-filled block) or the catalog is not a JSON array.
    #>
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][ValidateSet('Released', 'Test')][string]$Channel,
          [string[]]$Browsers = @('Edge', 'Chrome'), [Parameter(Mandatory)][string]$CatalogJson,
          [Nullable[int]]$AutoActivateMaxGroups = $null, [Nullable[int]]$BulkActivateConfirmThreshold = $null)
    $b = @($Browsers | Where-Object { $_ -in @('Edge', 'Chrome') } | Select-Object -Unique)
    if (-not $b.Count) { throw 'Browsers must hold Edge and/or Chrome.' }
    try { $cat = $CatalogJson | ConvertFrom-Json } catch { throw "The tenant catalog is not valid JSON: $($_.Exception.Message)" }
    if (-not ($CatalogJson.TrimStart().StartsWith('['))) { throw 'The tenant catalog must be a JSON array of tenants.' }
    if ($CatalogJson -match "(?m)^'@") { throw "The tenant catalog may not contain a line starting with '@." }
    $nl = if ($Text -match "`r`n") { "`r`n" } else { "`n" }
    $rules = [ordered]@{
        Channel   = @('(?m)^\$Channel = .*$', ('$Channel = ''{0}''' -f $Channel))
        Browsers  = @('(?m)^\$Browsers = .*$', ('$Browsers = @({0})' -f ((@($b) | ForEach-Object { "'$_'" }) -join ', ')))
        Catalog   = @("(?s)^\`$TenantCatalog = @'\r?\n.*?\r?\n'@", ("`$TenantCatalog = @'" + $nl + (($CatalogJson.Trim()) -replace "`r?`n", $nl) + $nl + "'@"))
        AutoMax   = @('(?m)^\$AutoActivateMaxGroups = .*$', ('$AutoActivateMaxGroups = {0}' -f $(if ($null -ne $AutoActivateMaxGroups) { [int]$AutoActivateMaxGroups } else { '$null' })))
        BulkConf  = @('(?m)^\$BulkActivateConfirmThreshold = .*$', ('$BulkActivateConfirmThreshold = {0}' -f $(if ($null -ne $BulkActivateConfirmThreshold) { [int]$BulkActivateConfirmThreshold } else { '$null' })))
    }
    $out = $Text
    foreach ($k in $rules.Keys) {
        $rx = [regex]::new($rules[$k][0], [System.Text.RegularExpressions.RegexOptions]::Multiline)
        if (-not $rx.IsMatch($out)) { throw "The script has no '$k' setting line -- refusing to build a half-filled Remediation." }
        $rep = $rules[$k][1]
        $out = $rx.Replace($out, { param($m) $rep }, 1)
    }
    return $out
}

function Get-PimActivatorCommands {
    <#
      PURE. The exact command lines for this environment: the two apps, the Remediation upload with its target, and the
      install for a server without Intune. -Target = a group id | 'AllDevices' | 'AllUsers'.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [ValidateSet('Released', 'Test')][string]$Channel = 'Released',
          [string]$Target = '', [string]$RemediationName = '', [string]$ClientId = '')
    $ch = Get-PimActivatorChannel -Channel $Channel
    $rn = if ("$RemediationName".Trim()) { "$RemediationName".Trim() } else { "PIM Activator settings ($($ch.label))" }
    $assign = if ($Target -ieq 'AllDevices') { ' -AssignAllDevices' } elseif ($Target -ieq 'AllUsers') { ' -AssignAllUsers' }
              elseif ("$Target" -match '^[0-9a-fA-F-]{36}$') { " -AssignToGroupId $Target" } else { '' }
    [ordered]@{
        appProd     = ".\Deploy-PimActivatorBackend.ps1 -TenantId $TenantId -Channel Released -DisplayName 'PIM Activator'"
        appTest     = ".\Deploy-PimActivatorBackend.ps1 -TenantId $TenantId -Channel Test -ExtensionId $($script:PimActivatorChannels.Test.id) -DisplayName 'PIM Activator (TEST)'"
        remediation = ".\Publish-PimActivatorRemediation.ps1 -TenantId $TenantId -Name '$rn' -DetectScript .\Detect-PimActivator.ps1 -RemediateScript .\Remediate-PimActivator.ps1$assign"
        server      = ".\Deploy-PimActivatorClient.ps1 -Scope Machine -Browser Both -Channel $Channel" + $(if ("$ClientId" -match '^[0-9a-fA-F-]{36}$') { " -ClientId $ClientId" } else { '' })
    }
}
