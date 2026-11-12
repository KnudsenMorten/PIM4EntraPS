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

function Get-PimInvardiaEnvironmentField {
    <# PURE. One text field ('displayName' | 'handle') of a cached pim.Settings 'InvardiaEnvironment' value (object or JSON
       text); '' = none. #>
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][string]$Field)
    if ($null -eq $Value) { return '' }
    try {
        if ($Value -is [string]) { if (-not $Value.Trim().StartsWith('{')) { return '' }; $Value = $Value | ConvertFrom-Json -ErrorAction Stop }
        $dn = $null
        if ($Value -is [System.Collections.IDictionary]) { if ($Value.Contains($Field)) { $dn = $Value[$Field] } }
        elseif ($Value.PSObject.Properties[$Field]) { $dn = $Value.$Field }
        if ($dn -isnot [string]) { return '' }
        return (ConvertTo-PimEnvironmentNameText -Value $dn -Max (Get-PimEnvironmentNameMax))
    } catch { return '' }
}

function Get-PimInvardiaEnvironmentDisplayName {
    <# PURE. Invardia's cached displayName from a pim.Settings 'InvardiaEnvironment' value (object or JSON text); '' = none. #>
    param([AllowNull()][object]$Value)
    return (Get-PimInvardiaEnvironmentField -Value $Value -Field 'displayName')
}

function Get-PimInvardiaEnvironmentMailName {
    <#
      PURE. MAIL-ENV correction (owner on SUP-2026-00497 "In the mail I see only prod and not example-prod"; framework 12.11a):
      the name a mail shows for an install with its key = Invardia's HANDLE (e.g. 'example-prod') -- a displayName such as
      "PROD" says nothing on its own. The displayName follows the handle only when it differs ("<handle> (<displayName>)").
      No handle cached = the displayName (an older cache); '' = nothing cached.
    #>
    param([AllowNull()][object]$Value)
    $h = Get-PimInvardiaEnvironmentField -Value $Value -Field 'handle'
    $d = Get-PimInvardiaEnvironmentField -Value $Value -Field 'displayName'
    if (-not $h) { return $d }
    if ($d -and $d -ine $h) { return "$h ($d)" }
    return $h
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

function Get-PimMailUnnamedEnvironmentText { <# PURE. LITERAL. The mail name when nothing at all names this environment. #> return 'Unnamed environment' }

function Resolve-PimMailEnvironmentName {
    <#
      PURE. MAIL-ENV (framework 12.11a, owner 2026-11-12 "owner mails name environments"): WHICH install sent a mail. Returns
      [ordered]@{ displayName; tag; tenantName; tenantId; source } -- displayName is NEVER empty.
        displayName  1. -Override ($global:PIM_EnvironmentName, a process-level name)
                     2. Invardia's cached HANDLE ('example-prod'; + " (<displayName>)" when that differs -- owner on
                        SUP-2026-00497: a displayName "PROD" alone names nothing) (pim.Settings 'InvardiaEnvironment', read on the uplink job with the
                        install key, last good value kept) -- ONLY when the install HAS a key (-HasInstallKey): a Community
                        install whose user did not say yes uses nothing Invardia once sent
                     3. the install's own configured 'EnvironmentName' (Settings > Naming & accounts)
                     4. the tenant display name (Graph organization, the tenant cache 'tenant-org')
                     5. "tenant <id>";  6. 'Unnamed environment'
        tag          the configured 'EnvironmentName' (the "[PROD]" the subject always carried) when it is not already the
                     display name; '' otherwise. A configured "PROD" with no other name is not enough to tell ~15 installs
                     apart, so then the TENANT name becomes the display name and "PROD" stays the tag.
      DISPLAY ONLY -- never a key. Never throws.
    #>
    param([AllowNull()][object]$Override = $null, [AllowNull()][object]$Invardia = $null, [bool]$HasInstallKey = $false,
          [AllowNull()][object]$Configured = $null, [AllowNull()][string]$TenantName = '', [AllowNull()][string]$TenantId = '')
    $max = Get-PimEnvironmentNameMax
    $ov = ConvertTo-PimEnvironmentNameText -Value $Override -Max $max
    # the HANDLE first (MAIL-ENV correction): "example-prod", never just "PROD"
    $inv = ''; if ($HasInstallKey) { $inv = Get-PimInvardiaEnvironmentMailName -Value $Invardia }
    $cfg = Get-PimConfiguredEnvironmentName -Value $Configured
    $tn = ConvertTo-PimEnvironmentNameText -Value $TenantName -Max $max
    $tid = ConvertTo-PimEnvironmentNameText -Value $TenantId -Max 64
    $dn = ''; $src = ''
    if ($ov) { $dn = $ov; $src = 'override' }
    elseif ($inv) { $dn = $inv; $src = 'invardia' }
    elseif ($cfg) { $dn = $cfg; $src = 'configured' }
    elseif ($tn) { $dn = $tn; $src = 'tenant' }
    elseif ($tid) { $dn = "tenant $tid"; $src = 'tenant-id' }
    else { $dn = Get-PimMailUnnamedEnvironmentText; $src = 'none' }
    $tag = ''
    if ($cfg -and $cfg -ne $dn) { $tag = $cfg }
    if ($src -eq 'configured' -and $tn -and $tn -ne $cfg) { $tag = $cfg; $dn = $tn; $src = 'configured+tenant' }
    if ($tag -and $tag -eq $dn) { $tag = '' }
    # "[PROD] example-prod (PROD)" says PROD twice: the displayName in brackets goes when it only repeats the tag
    if ($tag -and $src -eq 'invardia' -and $dn.EndsWith(" ($tag)", [StringComparison]::OrdinalIgnoreCase)) { $dn = $dn.Substring(0, $dn.Length - $tag.Length - 3) }
    return [ordered]@{ displayName = $dn; tag = $tag; tenantName = $tn; tenantId = $tid; source = $src }
}
