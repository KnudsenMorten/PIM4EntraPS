#Requires -Version 5.1
<#
.SYNOPSIS
    Discover and merge the PIM Activator per-tenant settings from Intune.

.DESCRIPTION
    The PIM Activator extension reads its per-tenant settings (tenantCatalog,
    bulkActivateConfirmThreshold, ...) from chrome.storage.managed, which the
    browser hydrates from the HKLM policy registry written by one or more Intune
    configuration profiles. A single tenant can carry those settings across
    BOTH Intune mechanisms at once:

      - Settings Catalog          (deviceManagement/configurationPolicies)
      - Administrative Templates   (deviceManagement/groupPolicyConfigurations,
                                    ADMX-backed)

    Some customers deploy the actual settings via a Settings Catalog policy AND a
    second Administrative Templates (ADMX) policy. To assemble the *effective*
    tenant settings we therefore have to enumerate EVERY PIM-Activator policy on
    BOTH endpoints and merge them.

    DISCOVERY MATCH (changed 2026-06-17):
      A policy is a PIM-Activator policy when its display name *contains* the
      literal substring  [PimActivator]  -- previously this was an exact match
      against the longer profile name (e.g. '[PimActivator] client settings').
      The new rule is a CONTAINS test, CASE-SENSITIVE, so that customers can name
      their policies freely (e.g. '[PimActivator] client settings',
      '[PimActivator] ADMX overrides', 'Corp - [PimActivator] - Ring 1') and all
      of them are picked up. Case-sensitive matches the exact casing the deploy
      scripts and ADMX/ADML ship ('[PimActivator]', capital P/A), so a
      mis-cased '[pimactivator]' is deliberately NOT treated as ours.

    MERGE PRECEDENCE:
      When the same setting key is present in more than one matching policy,
      ADMINISTRATIVE TEMPLATES (ADMX / groupPolicyConfigurations) WINS over
      Settings Catalog (configurationPolicies). Rationale: on the endpoint the
      ADMX profile is the canonical PIM Activator delivery vehicle (it ships our
      own PIM4EntraPS.PimActivator.admx and writes the 3rdparty\extensions\<id>\
      policy key directly), so when both are present the ADMX value is the
      intended override. Within a single endpoint type, the last-enumerated
      policy that carries a key wins (last-writer) -- callers that need a stable
      order should pass policies pre-sorted by displayName.

    This script is dot-sourceable: dot-source it to get the pure functions
    (Test-PimActivatorPolicyName / Get-PimActivatorEffectiveSettings) without
    running anything. The pure functions take an injectable REST invoker so they
    can be exercised offline with mock policies (see
    tests/Test-PimActivatorIntuneDiscovery.ps1). Native Graph REST only -- the
    default invoker uses Invoke-MgGraphRequest, but no Graph call happens unless
    you actually invoke the discovery against a live tenant.

.NOTES
    Required Graph scope (delegated or app): DeviceManagementConfiguration.Read.All
#>
[CmdletBinding()]
param(
    [switch]$Run
)

# The literal marker every PIM Activator Intune policy display name must contain.
# Case-sensitive on purpose -- this is the exact casing the ADMX/ADML + deploy
# scripts ship.
$script:PimActivatorPolicyMarker = '[PimActivator]'

function Test-PimActivatorPolicyName {
    <#
    .SYNOPSIS
        True when an Intune policy display name belongs to the PIM Activator.
    .DESCRIPTION
        CONTAINS test (not exact / not startswith) on the literal marker
        '[PimActivator]', CASE-SENSITIVE.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(ValueFromPipeline)][AllowNull()][string]$DisplayName
    )
    process {
        if ([string]::IsNullOrEmpty($DisplayName)) { return $false }
        # .Contains(string, StringComparison) is .NET Framework 4.x+ / .NET Core;
        # use IndexOf with Ordinal to stay PS 5.1-safe and explicitly case-sensitive.
        return ($DisplayName.IndexOf($script:PimActivatorPolicyMarker, [System.StringComparison]::Ordinal) -ge 0)
    }
}

function Get-PimActivatorEffectiveSettings {
    <#
    .SYNOPSIS
        Enumerate ALL [PimActivator] Intune policies across both endpoint types
        and merge their settings into one effective settings hashtable.

    .PARAMETER ConfigurationPolicies
        Pre-fetched Settings Catalog policies (deviceManagement/configurationPolicies
        .value). Each must expose .name (or .displayName) and a .settings property
        carrying a hashtable/dictionary of effective key=>value pairs. Optional --
        when omitted and -RestInvoker is supplied, they are fetched live.

    .PARAMETER GroupPolicyConfigurations
        Pre-fetched Administrative Templates policies
        (deviceManagement/groupPolicyConfigurations .value). Each must expose
        .displayName and a .settings property. Optional.

    .PARAMETER RestInvoker
        A scriptblock taking a single argument (the Graph URI) and returning the
        parsed response object (with a .value array). Used to fetch policies +
        their settings live. Inject a mock in tests. When omitted, the live
        Invoke-MgGraphRequest default is used.

    .OUTPUTS
        [pscustomobject] with:
          Settings   - merged hashtable of effective settings
          Matched    - array of { Type; Name; Id; Settings } that contributed
          Skipped    - array of policy display names that did NOT match
    #>
    [CmdletBinding()]
    param(
        [object[]]$ConfigurationPolicies,
        [object[]]$GroupPolicyConfigurations,
        [scriptblock]$RestInvoker
    )

    $baseUri = 'https://graph.microsoft.com/beta/deviceManagement'

    if (-not $RestInvoker) {
        $RestInvoker = { param($Uri) Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop }
    }

    # Helper: pull a property by either of two possible names (name/displayName).
    function _Prop {
        param($Obj, [string[]]$Names)
        foreach ($n in $Names) {
            if ($Obj -is [System.Collections.IDictionary]) {
                if ($Obj.Contains($n) -and $null -ne $Obj[$n]) { return $Obj[$n] }
            } elseif ($null -ne $Obj.PSObject.Properties[$n] -and $null -ne $Obj.$n) {
                return $Obj.$n
            }
        }
        return $null
    }

    # ---- Resolve the policy lists (live-fetch if not supplied) --------------
    if ($null -eq $ConfigurationPolicies) {
        $resp = & $RestInvoker "$baseUri/configurationPolicies"
        $ConfigurationPolicies = @()
        while ($resp) {
            if ($resp.value) { $ConfigurationPolicies += $resp.value }
            $next = _Prop $resp '@odata.nextLink'
            if ($next) { $resp = & $RestInvoker $next } else { $resp = $null }
        }
    }
    if ($null -eq $GroupPolicyConfigurations) {
        $resp = & $RestInvoker "$baseUri/groupPolicyConfigurations"
        $GroupPolicyConfigurations = @()
        while ($resp) {
            if ($resp.value) { $GroupPolicyConfigurations += $resp.value }
            $next = _Prop $resp '@odata.nextLink'
            if ($next) { $resp = & $RestInvoker $next } else { $resp = $null }
        }
    }

    $matched = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]

    # Helper: extract the settings dictionary for a policy. If the policy already
    # carries a .settings hashtable (mock / pre-fetched) we use it; otherwise we
    # fetch /settings live (Settings Catalog) or treat as empty.
    function _SettingsOf {
        param($Policy, [string]$Endpoint)
        $s = _Prop $Policy 'settings','Settings'
        if ($s -is [System.Collections.IDictionary]) { return $s }
        # Live Settings Catalog: fetch the /settings collection.
        if ($Endpoint -eq 'configurationPolicies') {
            $id = _Prop $Policy 'id','Id'
            if ($id) {
                $sResp = & $RestInvoker "$baseUri/configurationPolicies/$id/settings"
                $out = @{}
                foreach ($si in @($sResp.value)) {
                    $k = _Prop $si 'key','name','settingDefinitionId'
                    $v = _Prop $si 'value','simpleSettingValue'
                    if ($k) { $out[[string]$k] = $v }
                }
                return $out
            }
        }
        return @{}
    }

    # ---- Settings Catalog first (lower precedence) --------------------------
    foreach ($p in @($ConfigurationPolicies)) {
        $name = _Prop $p 'name','displayName'
        if (-not (Test-PimActivatorPolicyName -DisplayName ([string]$name))) {
            if ($name) { $skipped.Add([string]$name) }
            continue
        }
        $matched.Add([pscustomobject]@{
            Type     = 'SettingsCatalog'
            Name     = [string]$name
            Id       = [string](_Prop $p 'id','Id')
            Settings = (_SettingsOf -Policy $p -Endpoint 'configurationPolicies')
        })
    }

    # ---- Administrative Templates second (HIGHER precedence) ----------------
    foreach ($c in @($GroupPolicyConfigurations)) {
        $name = _Prop $c 'displayName','name'
        if (-not (Test-PimActivatorPolicyName -DisplayName ([string]$name))) {
            if ($name) { $skipped.Add([string]$name) }
            continue
        }
        $matched.Add([pscustomobject]@{
            Type     = 'AdminTemplate'
            Name     = [string]$name
            Id       = [string](_Prop $c 'id','Id')
            Settings = (_SettingsOf -Policy $c -Endpoint 'groupPolicyConfigurations')
        })
    }

    # ---- Merge. Settings Catalog applied first, Admin Templates overwrite. --
    # $matched is already ordered SettingsCatalog... then AdminTemplate...,
    # so a straight last-writer fold gives "Admin-Templates-wins" precedence,
    # and within one endpoint type the later-enumerated policy wins.
    $effective = @{}
    foreach ($m in $matched) {
        if ($m.Settings -is [System.Collections.IDictionary]) {
            # Snapshot keys to a plain array first (mutating $effective while
            # iterating $m.Settings.Keys is fine here, but $m.Settings is a
            # separate dict; copy keys defensively).
            $keys = [string[]]@($m.Settings.Keys)
            foreach ($k in $keys) {
                $effective[$k] = $m.Settings[$k]
            }
        }
    }

    # NOTE: wrap generic List<T> via .ToArray(), NOT @() -- @() on a
    # List[object]/List[string] of objects throws "Argument types do not match"
    # on PS 5.1/7 (documented PIM gotcha).
    return [pscustomobject]@{
        Settings = $effective
        Matched  = $matched.ToArray()
        Skipped  = $skipped.ToArray()
    }
}

# ---- Optional live run -----------------------------------------------------
if ($Run) {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -NoWelcome
        $ctx = Get-MgContext
    }
    Write-Host ("Connected: {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId) -ForegroundColor Cyan
    $result = Get-PimActivatorEffectiveSettings
    Write-Host ''
    Write-Host ("Matched {0} [PimActivator] policy/policies:" -f $result.Matched.Count) -ForegroundColor Cyan
    foreach ($m in $result.Matched) {
        Write-Host ("  - [{0}] {1}  ({2} setting key(s))" -f $m.Type, $m.Name, @($m.Settings.Keys).Count) -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host "Effective (merged) settings:" -ForegroundColor Cyan
    foreach ($k in @($result.Settings.Keys | Sort-Object)) {
        $v = $result.Settings[$k]
        if ($v -is [string] -and $v.Length -gt 120) { $v = $v.Substring(0,120) + '...' }
        Write-Host ("  {0} = {1}" -f $k, $v) -ForegroundColor Green
    }
}
