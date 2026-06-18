#Requires -Version 5.1
<#
.SYNOPSIS
    Offline test for the PIM Activator Intune policy discovery + merge logic
    (Get-PimActivatorTenantSettings.ps1). No Graph / no network.

.DESCRIPTION
    Feeds MOCK policies through Get-PimActivatorEffectiveSettings:
      - a Settings Catalog policy whose name CONTAINS '[PimActivator]'
      - an Administrative Templates (ADMX) policy whose name CONTAINS '[PimActivator]'
      - a NON-matching third-party policy
    and asserts:
      1. Both matching policies are enumerated (across both endpoint types).
      2. Their settings are merged into the effective settings.
      3. The non-matching policy is ignored (and reported as skipped).
      4. On a key present in BOTH, Administrative Templates wins (precedence).
      5. Case-sensitivity: '[pimactivator]' (wrong case) does NOT match.

    Exit code 0 = all pass, 1 = any failure. Run:
      pwsh -File .\tests\Test-PimActivatorIntuneDiscovery.ps1
      powershell -File .\tests\Test-PimActivatorIntuneDiscovery.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$module = Join-Path (Split-Path -Parent $here) 'Get-PimActivatorTenantSettings.ps1'
. $module

$pass = 0
$fail = 0
function Assert($cond, [string]$msg) {
    if ($cond) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  [FAIL] $msg" -ForegroundColor Red;   $script:fail++ }
}

Write-Host "=== PIM Activator Intune discovery + merge (offline) ===" -ForegroundColor Cyan
Write-Host ''

# ---- Mock policies --------------------------------------------------------
# Settings Catalog (configurationPolicies) -- uses .name
$mockConfigurationPolicies = @(
    [pscustomobject]@{
        id   = 'cp-0001'
        name = '[PimActivator] client settings'
        settings = @{
            tenantCatalog                = '[{"name":"Contoso","tenantId":"11111111-1111-1111-1111-111111111111"}]'
            bulkActivateConfirmThreshold = 5
        }
    }
    # NON-matching third-party policy -- must be ignored.
    [pscustomobject]@{
        id   = 'cp-9999'
        name = 'Corp Browser Hardening (Dashlane forcelist)'
        settings = @{ tenantCatalog = '[{"name":"SHOULD-NOT-APPEAR"}]' }
    }
    # Wrong-case marker -- must NOT match (case-sensitive).
    [pscustomobject]@{
        id   = 'cp-0002'
        name = '[pimactivator] lowercase decoy'
        settings = @{ bulkActivateConfirmThreshold = 99 }
    }
)

# Administrative Templates (groupPolicyConfigurations) -- uses .displayName
$mockGroupPolicyConfigurations = @(
    [pscustomobject]@{
        id          = 'gp-0001'
        displayName = 'Corp - [PimActivator] - ADMX overrides - Ring 1'
        settings = @{
            # Overrides the Settings Catalog value -> Admin Templates must win.
            bulkActivateConfirmThreshold = 10
            # New key only in the ADMX policy.
            extraAdmxOnlyKey             = 'admx-value'
        }
    }
)

# Invoker that fails loudly if anything tries to hit the network (everything is
# pre-fed, so it must never be called).
$noNet = { param($Uri) throw "Unexpected live Graph call to $Uri (test should be fully offline)" }

$result = Get-PimActivatorEffectiveSettings `
    -ConfigurationPolicies $mockConfigurationPolicies `
    -GroupPolicyConfigurations $mockGroupPolicyConfigurations `
    -RestInvoker $noNet

# ---- Assertions -----------------------------------------------------------
$matchedNames = @($result.Matched | ForEach-Object { $_.Name })
$matchedTypes = @($result.Matched | ForEach-Object { $_.Type })

Assert ($result.Matched.Count -eq 2) `
    "exactly 2 policies matched (got $($result.Matched.Count): $($matchedNames -join '; '))"

Assert ($matchedNames -contains '[PimActivator] client settings') `
    "Settings Catalog '[PimActivator] client settings' enumerated"

Assert ($matchedNames -contains 'Corp - [PimActivator] - ADMX overrides - Ring 1') `
    "ADMX 'Corp - [PimActivator] - ADMX overrides - Ring 1' enumerated"

Assert (($matchedTypes -contains 'SettingsCatalog') -and ($matchedTypes -contains 'AdminTemplate')) `
    "both endpoint types contributed (SettingsCatalog + AdminTemplate)"

Assert (-not ($matchedNames -contains 'Corp Browser Hardening (Dashlane forcelist)')) `
    "non-matching third-party policy NOT enumerated"

Assert ($result.Skipped -contains 'Corp Browser Hardening (Dashlane forcelist)') `
    "non-matching third-party policy reported as skipped"

Assert ($result.Skipped -contains '[pimactivator] lowercase decoy') `
    "wrong-case '[pimactivator]' policy skipped (case-sensitive match)"

# Merged settings: tenantCatalog only in Settings Catalog -> present.
Assert ($result.Settings['tenantCatalog'] -eq '[{"name":"Contoso","tenantId":"11111111-1111-1111-1111-111111111111"}]') `
    "tenantCatalog merged in from Settings Catalog"

# extraAdmxOnlyKey only in ADMX -> present.
Assert ($result.Settings['extraAdmxOnlyKey'] -eq 'admx-value') `
    "extraAdmxOnlyKey merged in from Admin Templates"

# bulkActivateConfirmThreshold in BOTH -> Admin Templates (10) wins over Settings Catalog (5).
Assert ($result.Settings['bulkActivateConfirmThreshold'] -eq 10) `
    "merge precedence: Admin Templates (10) wins over Settings Catalog (5) on shared key"

# The wrong-case decoy's value (99) must never leak into the merge.
Assert ($result.Settings['bulkActivateConfirmThreshold'] -ne 99) `
    "wrong-case decoy value (99) did NOT leak into merged settings"

# Spot-check the pure matcher directly.
Assert ((Test-PimActivatorPolicyName -DisplayName 'x [PimActivator] y') -eq $true)  "matcher: CONTAINS marker -> true"
Assert ((Test-PimActivatorPolicyName -DisplayName 'no marker here') -eq $false)      "matcher: no marker -> false"
Assert ((Test-PimActivatorPolicyName -DisplayName '[pimactivator]') -eq $false)      "matcher: wrong case -> false"
Assert ((Test-PimActivatorPolicyName -DisplayName $null) -eq $false)                 "matcher: null -> false"

Write-Host ''
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("  Pass: {0} / {1}" -f $pass, ($pass + $fail)) -ForegroundColor ($(if ($fail -eq 0) {'Green'} else {'Yellow'}))
Write-Host ("  Fail: {0}" -f $fail) -ForegroundColor ($(if ($fail -gt 0) {'Red'} else {'Gray'}))
if ($fail -gt 0) { exit 1 } else { exit 0 }
