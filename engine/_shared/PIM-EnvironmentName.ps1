<#
  PIM 100.70 / framework 8.14 ENV-NAME-MASTER -- the NAME this environment is SHOWN with.
  Invardia is the master of the display name (customers rename environments in the Invardia portal). The uplink job
  caches Invardia's answer in pim.Settings 'InvardiaEnvironment' (PIM-Uplink.ps1 Update-PimInvardiaEnvironmentCache);
  the product's own pim.Settings 'EnvironmentName' (Settings > Naming & accounts) stays the fallback.
  DISPLAY ONLY: a name is never a key -- nothing matches, joins, filters or decides on it (the tenant id is the identity).
  PURE, no I/O of its own (the caller hands the values or a getter), never throws. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimEnvironmentNameMax { <# PURE. The longest name shown (a literal). #> return 120 }

function ConvertTo-PimEnvironmentNameText {
    <# PURE. One display text: control characters and angle brackets out, whitespace folded, at most -Max characters. #>
    param([AllowNull()][object]$Value, [int]$Max = 120)
    if ($null -eq $Value) { return '' }
    $s = "$Value" -replace '[\x00-\x1F\x7F<>]', ' '
    $s = ($s -replace '\s+', ' ').Trim()
    if ($Max -gt 0 -and $s.Length -gt $Max) { $s = $s.Substring(0, $Max).Trim() }
    return $s
}

function Get-PimConfiguredEnvironmentName {
    <# PURE. The product's own configured name from a pim.Settings 'EnvironmentName' value: a string, or { name }. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return (ConvertTo-PimEnvironmentNameText -Value $Value -Max (Get-PimEnvironmentNameMax)) }
    try { if ($Value.PSObject.Properties['name']) { return (ConvertTo-PimEnvironmentNameText -Value $Value.name -Max (Get-PimEnvironmentNameMax)) } } catch { }
    return ''
}

function Get-PimInvardiaEnvironmentDisplayName {
    <# PURE. Invardia's cached displayName from a pim.Settings 'InvardiaEnvironment' value (object or JSON text); '' = none. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    try {
        if ($Value -is [string]) { if (-not $Value.Trim().StartsWith('{')) { return '' }; $Value = $Value | ConvertFrom-Json -ErrorAction Stop }
        $dn = $null
        if ($Value -is [System.Collections.IDictionary]) { if ($Value.Contains('displayName')) { $dn = $Value['displayName'] } }
        elseif ($Value.PSObject.Properties['displayName']) { $dn = $Value.displayName }
        if ($dn -isnot [string]) { return '' }
        return (ConvertTo-PimEnvironmentNameText -Value $dn -Max (Get-PimEnvironmentNameMax))
    } catch { return '' }
}

function Get-PimEnvironmentDisplayName {
    <#
      PURE. The name to SHOW for this environment: Invardia's cached displayName when present, else the configured
      'EnvironmentName', else ''. Either hand the two stored values (-Invardia / -Configured) or a getter
      (-GetSetting { param($Name) } -> the pim.Settings value; a throw = that value unknown). Never throws.
      DISPLAY ONLY -- never compare, match or key on the result.
    #>
    param([AllowNull()][object]$Invardia = $null, [AllowNull()][object]$Configured = $null, [AllowNull()][scriptblock]$GetSetting = $null)
    if ($GetSetting) {
        if (-not $PSBoundParameters.ContainsKey('Invardia')) { try { $Invardia = & $GetSetting 'InvardiaEnvironment' } catch { $Invardia = $null } }
        if (-not $PSBoundParameters.ContainsKey('Configured')) { try { $Configured = & $GetSetting 'EnvironmentName' } catch { $Configured = $null } }
    }
    $inv = Get-PimInvardiaEnvironmentDisplayName -Value $Invardia
    if ($inv) { return $inv }
    return (Get-PimConfiguredEnvironmentName -Value $Configured)
}
