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
    * the exact, self-contained commands: the apps (PROD + TEST), the Remediation build + upload, each for the group the
      customer chose (or nobody yet -- never all users / all devices; 2026-10-08), the
      server / no-Intune install.
#>

$script:PimActivatorChannels = [ordered]@{
    Released = [ordered]@{ id = 'eheocihmlppcophaeakmdenhgcookkab'; updateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'; label = 'PROD'; appName = 'PIM Activator' }
    Test     = [ordered]@{ id = 'glldnbmjpdkjemcnficagdhgienfdpoo'; updateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates-test.xml'; label = 'TEST'; appName = 'PIM Activator (TEST)' }
}
$script:PimActivatorMinimumVersion = '1.6.136'

function Get-PimActivatorInstallSourcePattern {
    <#
      PURE. 97.2 (owner 2026-10-08: "step 4 url is wrong"): the ExtensionInstallSources pattern for an update URL = its
      FOLDER + '*' (https://<host>/<path>/updates.xml -> https://<host>/<path>/*) -- exactly where the page tells Edge
      to install from, never a whole site. Follows the update URL wherever it is hosted.
    #>
    param([Parameter(Mandatory)][string]$UpdateUrl)
    $u = $null
    if (-not [uri]::TryCreate("$UpdateUrl".Trim(), [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https') { throw "The update URL '$UpdateUrl' is not an https URL." }
    $path = $u.AbsolutePath; $dir = $path.Substring(0, $path.LastIndexOf('/') + 1)
    "https://$($u.Authority)$dir*"
}

function Get-PimActivatorChannel {
    <# PURE. Released | Test -> @{ id; updateUrl; label; appName }. Throws on anything else. #>
    param([Parameter(Mandatory)][string]$Channel)
    foreach ($k in $script:PimActivatorChannels.Keys) { if ($k -ieq "$Channel".Trim()) { return $script:PimActivatorChannels[$k] } }
    throw "Unknown PIM Activator channel '$Channel' (Released or Test)."
}

function Get-PimActivatorEdgePolicy {
    <#
      PURE. The Edge management service policy for the chosen extensions -- the exact shape of the operator's working
      internal policy "Extension, Force-install PIM Activator (TEST + PROD)" (admin center, 2026-10-07): ONE Cloud policy
      with BOTH settings,
        ExtensionSettings        {"*":{}, "<id>":{installation_mode, blocked_permissions, runtime_blocked_hosts,
                                  runtime_allowed_hosts, minimum_version_required, override_update_url, update_url,
                                  toolbar_state}, ...}
        ExtensionInstallForcelist "<id>;<update url>" per extension
      The service does NOT merge extension lists across policies, so both channels go in one policy when both are wanted.
      -Extensions: @( @{ channel = 'Released'|'Test'; minimumVersion; toolbarState = default_hidden|default_shown|
      force_shown; blockedHosts = @(); allowedHosts = @(); blockedPermissions = @(); overrideUpdateUrl = $true;
      installationMode = force_installed|normal_installed } ). -Channels is the short form (defaults for each).
      Returns @{ installSources; minimumVersion; extensionSettingsJson; extensionSettings (object); forcelist (array);
      forcelistText; extensions (the normalised input) }.
    #>
    param([string[]]$Channels = @('Released'), [object[]]$Extensions = @())
    $list = @($Extensions | Where-Object { $_ })
    if (-not $list.Count) { $list = @($Channels | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { @{ channel = $_ } }) }
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } } elseif ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.$n } }
    $hosts = { param($v) @(@($v) | ForEach-Object { "$_" -split '[\r\n,]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique) }
    $settings = [ordered]@{ '*' = [ordered]@{} }
    $force = New-Object System.Collections.Generic.List[string]
    $norm = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($e in $list) {
        $ch = Get-PimActivatorChannel -Channel "$(& $get $e 'channel')"
        if ($seen[$ch.id]) { continue }; $seen[$ch.id] = $true
        $min = "$(& $get $e 'minimumVersion')".Trim(); if (-not $min) { $min = $script:PimActivatorMinimumVersion }
        if ($min -notmatch '^\d+(\.\d+){0,3}$') { throw "Minimum version '$min' for $($ch.label) is not a version (e.g. 1.6.136)." }
        $tb = "$(& $get $e 'toolbarState')".Trim(); if (-not $tb) { $tb = 'default_hidden' }
        if ($tb -notin @('default_hidden', 'default_shown', 'force_shown')) { throw "Toolbar state '$tb' is not one of default_hidden, default_shown, force_shown." }
        $mode = "$(& $get $e 'installationMode')".Trim(); if (-not $mode) { $mode = 'force_installed' }
        if ($mode -notin @('force_installed', 'normal_installed')) { throw "Installation setting '$mode' is not force_installed or normal_installed." }
        $ovr = & $get $e 'overrideUpdateUrl'; $ovr = if ($null -eq $ovr -or "$ovr" -eq '') { $true } else { [bool]$ovr -and "$ovr" -ne 'false' }
        # @(): a script block returning an empty or one-item array unrolls it ($null / a bare string) -- the policy needs []
        $blocked = @(& $hosts (& $get $e 'blockedHosts')); $allowed = @(& $hosts (& $get $e 'allowedHosts'))
        $perms = @(@(& $get $e 'blockedPermissions') | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
        $settings[$ch.id] = [ordered]@{
            installation_mode = $mode; blocked_permissions = $perms; runtime_blocked_hosts = $blocked; runtime_allowed_hosts = $allowed
            minimum_version_required = $min; override_update_url = [bool]$ovr; update_url = $ch.updateUrl; toolbar_state = $tb }
        $force.Add("$($ch.id);$($ch.updateUrl)")
        $norm.Add([ordered]@{ channel = $(if ($ch.label -eq 'TEST') { 'Test' } else { 'Released' }); id = $ch.id; name = $ch.appName; updateUrl = $ch.updateUrl
                              minimumVersion = $min; toolbarState = $tb; installationMode = $mode; overrideUpdateUrl = [bool]$ovr
                              blockedHosts = $blocked; allowedHosts = $allowed; blockedPermissions = $perms })
    }
    # Compact, like the admin center's own export (and so empty arrays stay [] -- ConvertTo-Json keeps them as [] only
    # with -InputObject on the whole object).
    $json = ConvertTo-Json -InputObject $settings -Depth 6 -Compress
    $json = $json -replace '"\*":\{\}', '"*":{}' -replace '"\*":\[\]', '"*":{}'
    # ExtensionInstallSources: one pattern row per distinct update-URL folder of the chosen extensions (owner 2026-10-08).
    $src = @($norm | ForEach-Object { Get-PimActivatorInstallSourcePattern -UpdateUrl $_.updateUrl } | Select-Object -Unique)
    return [ordered]@{ installSources = ($src -join "`n"); installSourcesList = @($src); minimumVersion = $script:PimActivatorMinimumVersion
                       extensionSettingsJson = $json; extensionSettings = $settings; forcelist = $force.ToArray(); forcelistText = ($force.ToArray() -join ', ')
                       extensions = $norm.ToArray() }
}

function Get-PimActivatorPublishedVersion {
    <#
      PURE. The version an update manifest (updates.xml / updates-test.xml, Google update2 format) publishes for an
      extension id; '' when the text holds none.
    #>
    param([string]$UpdateXml, [Parameter(Mandatory)][string]$ExtensionId)
    if (-not "$UpdateXml".Trim()) { return '' }
    $rx = "(?s)<app\s+appid=['""]$([regex]::Escape($ExtensionId))['""][^>]*>.*?<updatecheck\b[^>]*\bversion=['""]([0-9.]+)['""]"
    $m = [regex]::Match($UpdateXml, $rx)
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function New-PimActivatorCatalog {
    <#
      PURE. The tenant catalog (the JSON the extension reads) for THIS environment. -ClientId = the Activator app of the
      channel. Optional prefixes narrow what the popup lists. Returns the JSON text (an array of one tenant).
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId,
          [string]$DefaultJustification = 'Change in infrastructure', [int]$DefaultDurationHours = 8,
          [string]$Prefix = '', [string]$EntraPrefix = '', [string]$AzurePrefix = '',
          # 97.2 (owner 2026-10-08: "the custom json structure for multi-tenant (optional). so the admins can select from
          # different tenants"): more tenants for the popup's tenant switcher, a JSON array (ConvertTo-PimActivatorExtraTenants).
          [string]$AdditionalTenantsJson = '')
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ("$TenantId" -notmatch $guid) { throw "TenantId is not a GUID: '$TenantId'" }
    if ("$ClientId" -notmatch $guid) { throw "ClientId (the PIM Activator app) is not a GUID: '$ClientId'" }
    if ($DefaultDurationHours -lt 1 -or $DefaultDurationHours -gt 24) { throw 'DefaultDurationHours must be 1-24.' }
    $t = [ordered]@{ name = "$Name".Trim(); tenantId = "$TenantId".ToLowerInvariant(); clientId = "$ClientId".ToLowerInvariant()
                     defaultJustification = "$DefaultJustification"; defaultDurationHours = $DefaultDurationHours }
    if ("$Prefix".Trim())      { $t['prefix'] = "$Prefix".Trim() }
    if ("$EntraPrefix".Trim()) { $t['entraPrefix'] = "$EntraPrefix".Trim() }
    if ("$AzurePrefix".Trim()) { $t['azurePrefix'] = "$AzurePrefix".Trim() }
    $extra = @(ConvertTo-PimActivatorExtraTenants -Json $AdditionalTenantsJson -ExcludeTenantId $t.tenantId)
    return (ConvertTo-Json -InputObject (@($t) + $extra) -Depth 4)
}

function ConvertTo-PimActivatorExtraTenants {
    <#
      PURE. The OPTIONAL extra tenants of the catalog (managed-schema.json tenantCatalog: an array of { name, tenantId,
      clientId, defaultJustification?, defaultDurationHours?, prefix?, entraPrefix?, azurePrefix?, groupNameFilter?,
      entraGroupRegex?, azureGroupRegex?, bulkActivateConfirmThreshold? }). Empty = none (one tenant, as before).
      Throws on anything the extension would not read: not an array, a missing name / tenant id / client id, a key it does
      not know, a value out of range, the same tenant twice. An entry for this environment's own tenant (-ExcludeTenantId)
      is skipped: that tenant is always the first entry already.
      Returns the normalised entries (ordered, ids lower case).
    #>
    param([string]$Json, [string]$ExcludeTenantId = '')
    if (-not "$Json".Trim()) { return @() }
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if (-not "$Json".TrimStart().StartsWith('[')) { throw 'The extra tenants must be a JSON array: [ { "name": ..., "tenantId": ..., "clientId": ... } ].' }
    try { $arr = ConvertFrom-Json -InputObject "$Json" -ErrorAction Stop } catch { throw "The extra tenants are not valid JSON: $($_.Exception.Message)" }
    # Windows PowerShell 5.1 can answer broken text with $null instead of an error -- that is not "no tenants"
    if ($null -eq $arr -and "$Json".Trim() -notmatch '^\[\s*\]$') { throw 'The extra tenants are not valid JSON (nothing could be read from it).' }
    $known = @('name', 'tenantId', 'clientId', 'defaultJustification', 'defaultDurationHours', 'prefix', 'entraPrefix', 'azurePrefix', 'groupNameFilter', 'entraGroupRegex', 'azureGroupRegex', 'bulkActivateConfirmThreshold')
    $seen = @{}; if ("$ExcludeTenantId".Trim()) { $seen["$ExcludeTenantId".ToLowerInvariant()] = 'this environment' }
    $out = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($e in @($arr)) {
        $i++
        if ($null -eq $e -or $e -isnot [pscustomobject]) { throw "Extra tenant #${i} is not an object." }
        $bad = @($e.PSObject.Properties.Name | Where-Object { $_ -cnotin $known })
        if ($bad.Count) { throw "Extra tenant #${i}: unknown key(s) $($bad -join ', ') (allowed: $($known -join ', '))." }
        $n = "$($e.name)".Trim(); $tid = "$($e.tenantId)".Trim(); $cid = "$($e.clientId)".Trim()
        if (-not $n) { throw "Extra tenant #${i}: 'name' is required." }
        if ($tid -notmatch $guid) { throw "Extra tenant #$i ($n): 'tenantId' must be a GUID." }
        if ($cid -notmatch $guid) { throw "Extra tenant #$i ($n): 'clientId' (its PIM Activator app) must be a GUID." }
        $k = $tid.ToLowerInvariant()
        # this environment's own tenant is always the FIRST entry (built from the Settings step): an entry for it here is
        # the sample's first row -- skipped, not doubled
        if ("$ExcludeTenantId".Trim() -and $k -eq "$ExcludeTenantId".Trim().ToLowerInvariant()) { continue }
        if ($seen.ContainsKey($k)) { throw "Extra tenant #$i ($n): tenant $k is already in the catalog ($($seen[$k]))." }
        $seen[$k] = $n
        $o = [ordered]@{ name = $n; tenantId = $k; clientId = $cid.ToLowerInvariant() }
        foreach ($p in $known | Select-Object -Skip 3) {
            if (-not $e.PSObject.Properties[$p] -or $null -eq $e.$p -or "$($e.$p)" -eq '') { continue }
            $v = $e.$p
            if ($p -eq 'defaultDurationHours') { if ("$v" -notmatch '^\d+$' -or [int]$v -lt 1 -or [int]$v -gt 24) { throw "Extra tenant #$i ($n): defaultDurationHours must be 1-24." }; $v = [int]$v }
            elseif ($p -eq 'bulkActivateConfirmThreshold') { if ("$v" -notmatch '^\d+$' -or [int]$v -lt 1 -or [int]$v -gt 100) { throw "Extra tenant #$i ($n): bulkActivateConfirmThreshold must be 1-100." }; $v = [int]$v }
            elseif ($p -in @('entraPrefix', 'azurePrefix') -and $v -is [array]) { $v = @($v | ForEach-Object { "$_" }) }
            else { $v = "$v" }
            $o[$p] = $v
        }
        $out.Add($o)
    }
    return $out.ToArray()   # unrolled on purpose: callers collect with @()
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

# ---------------------------------------------------------------------------------------------------------------------
# 97.2 (owner 2026-10-08: "remove these buttons and leave only the cmdlets to run ... customer must define who (group) to
# deploy to - not everyone"; then "give option to dropdown group ... the cmdlets doesn't add an assignment by default"; and
# "this guide is wrong as it refers to 3 files, but the cmdlets show is missing 2 of them"). The page shows ONLY commands.
# Each command is SELF-CONTAINED (one download from invardia.com/support/pim, nothing else to fetch) and names WHO it
# deploys to: the customer's chosen group (-AssignToGroupId), or nobody yet when no group is chosen. Never all users / all
# devices.
# ---------------------------------------------------------------------------------------------------------------------

# The shipped Detect / Remediate scripts. In the repository they are read from intune-remediation\ next to this file; the
# standalone Publish-PimActivatorRemediation.ps1 that Build-PimSupportScripts makes carries them EMBEDDED (the builder
# fills the table on the next line), so the published script needs no other file.
$script:PimActivatorBuildDir = $PSScriptRoot
$script:PimActivatorEmbeddedTemplates = @{}   # BUILD-EMBED: intune-remediation/Detect-PimActivator.ps1, intune-remediation/Remediate-PimActivator.ps1

function Get-PimActivatorRemediationTemplate {
    <#
      The shipped text of Detect-PimActivator.ps1 / Remediate-PimActivator.ps1: the embedded copy when this runs as the
      standalone download, else the file in intune-remediation\. Decoded like [IO.File]::ReadAllText (a BOM is dropped),
      so both paths give the same text. Throws when neither is there.
    #>
    param([Parameter(Mandatory)][ValidateSet('Detect-PimActivator.ps1', 'Remediate-PimActivator.ps1')][string]$Name)
    $b64 = $script:PimActivatorEmbeddedTemplates[$Name]
    if ($b64) {
        $ms = New-Object IO.MemoryStream (, [Convert]::FromBase64String($b64))
        $sr = New-Object IO.StreamReader($ms, (New-Object Text.UTF8Encoding($false)), $true)
        try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
    }
    foreach ($d in @($script:PimActivatorBuildDir, $PSScriptRoot) | Where-Object { $_ } | Select-Object -Unique) {
        $p = Join-Path $d "intune-remediation\$Name"
        if (Test-Path -LiteralPath $p) { return [IO.File]::ReadAllText($p) }
    }
    throw "The shipped $Name was not found (embedded or in intune-remediation\). Download the standalone script again from https://invardia.com/support/pim/Publish-PimActivatorRemediation.ps1."
}

function New-PimActivatorRemediationPair {
    <#
      The filled Detect + Remediate pair for one environment -- the SAME text the Manager's Operations > PIM Activator
      builds and the standalone Publish-PimActivatorRemediation.ps1 builds from its parameters (one function, so the two
      cannot differ). Returns @{ channel; catalog; detect; remediate }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [string]$Name = 'PIM',
          [ValidateSet('Released', 'Test')][string]$Channel = 'Released', [string[]]$Browsers = @('Edge', 'Chrome'),
          [string]$DefaultJustification = 'Change in infrastructure', [int]$DefaultDurationHours = 8,
          [string]$Prefix = '', [string]$EntraPrefix = '', [string]$AzurePrefix = '',
          [Nullable[int]]$AutoActivateMaxGroups = $null, [Nullable[int]]$BulkActivateConfirmThreshold = $null,
          [string]$AdditionalTenantsJson = '')
    $cat = New-PimActivatorCatalog -Name $(if ("$Name".Trim()) { $Name } else { 'PIM' }) -TenantId $TenantId -ClientId $ClientId -DefaultJustification $DefaultJustification `
        -DefaultDurationHours $DefaultDurationHours -Prefix $Prefix -EntraPrefix $EntraPrefix -AzurePrefix $AzurePrefix -AdditionalTenantsJson $AdditionalTenantsJson
    $det = Set-PimActivatorRemediationSettings -Text (Get-PimActivatorRemediationTemplate -Name 'Detect-PimActivator.ps1') -Channel $Channel -Browsers $Browsers -CatalogJson $cat -AutoActivateMaxGroups $AutoActivateMaxGroups -BulkActivateConfirmThreshold $BulkActivateConfirmThreshold
    $rem = Set-PimActivatorRemediationSettings -Text (Get-PimActivatorRemediationTemplate -Name 'Remediate-PimActivator.ps1') -Channel $Channel -Browsers $Browsers -CatalogJson $cat -AutoActivateMaxGroups $AutoActivateMaxGroups -BulkActivateConfirmThreshold $BulkActivateConfirmThreshold
    [ordered]@{ channel = $Channel; catalog = $cat; detect = $det; remediate = $rem }
}

function ConvertTo-PimActivatorTargets {
    <#
      PURE. pim.Settings['ActivatorTargets'] normalised: @{ Released = @{ groupId; displayName } | $null; Test = ... }.
      A value without a GUID group id is no target (never "everyone").
    #>
    param($Value)
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } } elseif ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.$n } }
    $out = [ordered]@{ Released = $null; Test = $null }
    foreach ($c in 'Released', 'Test') {
        $t = & $get $Value $c
        $gid = "$(& $get $t 'groupId')".Trim()
        if ($gid -match $guid) {
            $out[$c] = [ordered]@{ groupId = $gid.ToLowerInvariant(); displayName = ("$(& $get $t 'displayName')" -replace '[\x00-\x1F\x7F]', ' ').Trim() }
        }
    }
    $out
}

function ConvertTo-PimActivatorPsLiteral {
    # PURE. A PowerShell single-quoted literal ('' doubles a quote).
    param([string]$Text)
    "'" + ("$Text" -replace "'", "''") + "'"
}

function Get-PimActivatorWho {
    # PURE. What a command deploys to, in words: the group, or nobody yet.
    param($Target, [string]$Channel = 'Released')
    $label = if ($Channel -eq 'Test') { 'TEST' } else { 'PROD' }
    if ($Target -and "$($Target.groupId)") {
        $n = if ("$($Target.displayName)".Trim()) { "$($Target.displayName)" } else { "$($Target.groupId)" }
        return "$label -- $n"
    }
    "$label -- no group chosen yet (nobody gets it until you assign a group)"
}

function Get-PimActivatorCommands {
    <#
      PURE. The exact, self-contained command lines for this environment. Each needs only its own script from
      invardia.com/support/pim -- no other file. -Targets = the ActivatorTargets setting; a channel without a group gets
      its command WITHOUT -AssignToGroupId (the scripts then assign nobody and say so). -Settings = the Settings step
      (name, defaultJustification, defaultDurationHours, prefix, entraPrefix, azurePrefix, autoActivateMaxGroups,
      bulkActivateConfirmThreshold, browsers) for the Remediation + server commands. -TestSharesProdApp: there is no
      TEST app because the PROD app carries the TEST redirects -> the TEST group is added to the PROD app.
      Returns @{ appProd; appTest; remediationProd; remediationTest; remediation (= -Channel); server (= -Channel);
                 whoProd; whoTest; who (= -Channel) }. A Remediation command is '' while its channel has no app id.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [ValidateSet('Released', 'Test')][string]$Channel = 'Released',
          $Targets = $null, $Settings = $null, [string]$ClientId = '', [string]$TestClientId = '',
          [string]$DailyTime = '', [int]$EveryHours = 0, [switch]$TestSharesProdApp)
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $tg = ConvertTo-PimActivatorTargets $Targets
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } } elseif ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.$n } }
    $asg = { param($c) if ($tg[$c]) { " -AssignToGroupId $($tg[$c].groupId)" } else { '' } }
    $appProd = ".\Deploy-PimActivatorBackend.ps1 -TenantId $TenantId -Channel Released -DisplayName 'PIM Activator'" + (& $asg 'Released')
    $appTest = if ($TestSharesProdApp) { ".\Deploy-PimActivatorBackend.ps1 -TenantId $TenantId -Channel Both -DisplayName 'PIM Activator'" + (& $asg 'Test') }
               else { ".\Deploy-PimActivatorBackend.ps1 -TenantId $TenantId -Channel Test -ExtensionId $($script:PimActivatorChannels.Test.id) -DisplayName 'PIM Activator (TEST)'" + (& $asg 'Test') }
    # the settings shared by the Remediation + the server install (step 2)
    $name = "$(& $get $Settings 'name')".Trim(); if (-not $name) { $name = 'PIM' }
    $just = "$(& $get $Settings 'defaultJustification')".Trim(); if (-not $just) { $just = 'Change in infrastructure' }
    $hrs = "$(& $get $Settings 'defaultDurationHours')"; $hrs = if ($hrs -match '^\d+$' -and [int]$hrs -ge 1 -and [int]$hrs -le 24) { [int]$hrs } else { 8 }
    $br = @(@(& $get $Settings 'browsers') | Where-Object { "$_" -in @('Edge', 'Chrome') } | Select-Object -Unique); if (-not $br.Count) { $br = @('Edge', 'Chrome') }
    $opt = ''
    foreach ($k in 'Prefix', 'EntraPrefix', 'AzurePrefix') { $v = "$(& $get $Settings ($k.Substring(0,1).ToLower() + $k.Substring(1)))".Trim(); if ($v) { $opt += " -$k $(ConvertTo-PimActivatorPsLiteral $v)" } }
    foreach ($k in 'AutoActivateMaxGroups', 'BulkActivateConfirmThreshold') { $v = "$(& $get $Settings ($k.Substring(0,1).ToLower() + $k.Substring(1)))".Trim(); if ($v -match '^\d+$') { $opt += " -$k $v" } }
    # the optional extra tenants (multi-tenant catalog), validated, compact, as one PowerShell literal
    $xt = @(ConvertTo-PimActivatorExtraTenants -Json "$(& $get $Settings 'additionalTenants')" -ExcludeTenantId $TenantId)
    $xtArg = if ($xt.Count) { ' -AdditionalTenantsJson ' + (ConvertTo-PimActivatorPsLiteral (ConvertTo-Json -InputObject $xt -Depth 4 -Compress)) } else { '' }
    $opt += $xtArg
    $sched = if ($EveryHours -ge 1 -and $EveryHours -le 23) { " -EveryHours $EveryHours" } elseif ("$DailyTime" -match '^\d{2}:\d{2}$' -and "$DailyTime" -ne '09:00') { " -DailyTime $DailyTime" } else { '' }
    $cidFor = { param($c) $x = if ($c -eq 'Test' -and "$TestClientId" -match $guid) { $TestClientId } elseif ("$ClientId" -match $guid) { $ClientId } else { '' }; "$x".ToLowerInvariant() }
    $rem = {
        param($c)
        $cid = & $cidFor $c
        if (-not $cid) { return '' }
        ".\Publish-PimActivatorRemediation.ps1 -TenantId $TenantId -Channel $c -ClientId $cid -CatalogName $(ConvertTo-PimActivatorPsLiteral $name) -DefaultJustification $(ConvertTo-PimActivatorPsLiteral $just) -DefaultDurationHours $hrs -Browsers $($br -join ',')$opt" + (& $asg $c) + $sched
    }
    $srv = {
        param($c)
        $cid = & $cidFor $c
        $line = ".\Deploy-PimActivatorClient.ps1 -Scope Machine -Browser Both -Channel $c"
        if ($cid) { $line += " -TenantId $TenantId -ClientId $cid -TenantName $(ConvertTo-PimActivatorPsLiteral $name) -DefaultJustification $(ConvertTo-PimActivatorPsLiteral $just) -DefaultDurationHours $hrs$xtArg" }
        $line
    }
    [ordered]@{
        appProd = $appProd; appTest = $appTest
        remediationProd = (& $rem 'Released'); remediationTest = (& $rem 'Test'); remediation = (& $rem $Channel)
        server = (& $srv $Channel)
        whoProd = (Get-PimActivatorWho -Target $tg['Released'] -Channel Released); whoTest = (Get-PimActivatorWho -Target $tg['Test'] -Channel Test)
        who = (Get-PimActivatorWho -Target $tg[$Channel] -Channel $Channel)
    }
}

