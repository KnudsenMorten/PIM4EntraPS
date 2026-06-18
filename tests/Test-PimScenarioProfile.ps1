#Requires -Version 5.1
<#
.SYNOPSIS
    Deployment-topology (scenario) descriptor classification + resolution test
    (REQUIREMENTS s31). The test/release GATE for PIM-ScenarioProfile.ps1: all six
    supported topologies (S1-S6) are declared, every descriptor is valid against
    the generic dimension contract, the cross-field invariants hold, and each
    resolves to the correct existing runtime knobs (configVariant, update source,
    ring gating, license edition, hosting, SPN model, sync model).

.DESCRIPTION
    All OFFLINE (no live tenant, no server boot, no real deploy). Layers:

      1. CONTRACT      -- the generic dimension contract is complete + reusable
                          (no PIM specifics leak in); every dimension lists values.
      2. CATALOG       -- exactly S1-S6 are present, unique ids, each carries every
                          generic dimension with a recognised value.
      3. INVARIANTS    -- Test-PimScenarioDescriptor passes for every shipped
                          scenario; a hand-broken descriptor fails (fail-safe).
      4. RESOLUTION    -- Resolve-PimScenarioContext maps each scenario onto the
                          right existing knobs (the directive's S1-S6 wording).
      5. ACTIVE/APPLY  -- Get-PimActiveScenario honours an override + the persisted
                          store + the S1 default; Set-PimScenarioContext sets the
                          existing globals (PIM_ConfigVariant etc.) and is pure of
                          new behaviour.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1')

# ---- in-memory settings store stub (drives Get-PimActiveScenario path) ----------
$script:__store = @{}
function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
function Reset-Store {
    $script:__store = @{}
    $global:PIM_ActiveScenario = $null
    $global:PIM_NamingConventions = $null
    $global:PIM_ConfigVariant = $null
    $global:PIM_ScenarioRingGated = $null
    $global:PIM_DistributionEdition = $null
}
Reset-Store

Write-Host "`n== 1. GENERIC DIMENSION CONTRACT ==" -ForegroundColor Cyan
$dims = Get-PimGenericScenarioDimensions
$expectedDims = @('role','edition','updateSource','hostingLocation','syncFileLocation','spnModel','syncModel','licenseTier')
T 'contract declares all 8 generic dimensions' (@($dims.Keys).Count -eq 8 -and (-not (@($expectedDims | Where-Object { $_ -notin $dims.Keys }))))
$allDimsHaveValues = $true
foreach ($k in $dims.Keys) { if (@($dims[$k].values).Count -lt 1 -or -not "$($dims[$k].description)".Trim()) { $allDimsHaveValues = $false } }
T 'every dimension lists allowed values + a description' $allDimsHaveValues
# Reusability: the contract text must not name PIM-specific knobs (configVariant,
# PIM_, SQLEXPRESS) -- those live in the bindings, not the generic contract.
$contractText = ($dims.GetEnumerator() | ForEach-Object { "$($_.Value.description)" }) -join ' '
T 'generic contract is solution-agnostic (no PIM-specific knob names)' (-not ($contractText -match 'configVariant|PIM_|SQLEXPRESS|pim\.'))

Write-Host "`n== 2. SCENARIO CATALOG (S1-S6) ==" -ForegroundColor Cyan
$catalog = Get-PimScenarioCatalog
T 'catalog has exactly 6 scenarios' (@($catalog).Count -eq 6)
$ids = @($catalog | ForEach-Object { "$($_.id)" })
T 'ids are exactly S1..S6 (unique)' (((@($ids | Sort-Object -Unique)) -join ',') -eq 'S1,S2,S3,S4,S5,S6')
$everyDimPresent = $true
foreach ($s in $catalog) {
    foreach ($k in $dims.Keys) {
        $v = "$(Get-PimScenarioValue -Object $s -Key $k)"
        if (-not $v.Trim() -or $v -notin $dims[$k].values) { $everyDimPresent = $false }
    }
    if (-not "$($s.label)".Trim() -or -not "$($s.summary)".Trim()) { $everyDimPresent = $false }
    if (-not $s.bindings) { $everyDimPresent = $false }
}
T 'every scenario carries all generic dimensions with recognised values + label/summary/bindings' $everyDimPresent

Write-Host "`n== 3. DESCRIPTOR INVARIANTS ==" -ForegroundColor Cyan
$allValid = $true
foreach ($s in $catalog) {
    $r = Test-PimScenarioDescriptor -Scenario $s
    if (-not $r.ok) { $allValid = $false; Write-Host "    $($s.id): $($r.errors -join '; ')" -ForegroundColor DarkYellow }
}
T 'every shipped scenario passes Test-PimScenarioDescriptor' $allValid
# fail-safe: a hand-broken descriptor (single tenant claiming a master pull) fails
$broken = [pscustomobject]@{ id='SX'; role='single'; edition='community'; updateSource='from-master-by-rings'; hostingLocation='in-tenant'; syncFileLocation='none'; spnModel='local-spn'; syncModel='none'; licenseTier='Community' }
T 'a broken descriptor (single + from-master) fails validation' (-not (Test-PimScenarioDescriptor -Scenario $broken).ok)
# fail-safe: multi-tenant SPN on a non-central-managed scenario fails
$broken2 = [pscustomobject]@{ id='SY'; role='single'; edition='community'; updateSource='github'; hostingLocation='in-tenant'; syncFileLocation='none'; spnModel='multi-tenant-spn'; syncModel='none'; licenseTier='Community' }
T 'a broken descriptor (single + multi-tenant-spn) fails validation' (-not (Test-PimScenarioDescriptor -Scenario $broken2).ok)

Write-Host "`n== 4. RESOLUTION TO EXISTING KNOBS ==" -ForegroundColor Cyan
# S1 -- single, internal, in-tenant, internal-automateit update, Pro-DesignPartner, local config
$c1 = Resolve-PimScenarioContext -Scenario 'S1'
T 'S1 -> configVariant=local, updateSource=sync-automateit, ringGated=$false, edition=Pro-DesignPartner' `
    ($c1.configVariant -eq 'local' -and $c1.updateSourceProfile -eq 'sync-automateit' -and -not $c1.ringGated -and $c1.activeEdition -eq 'Pro-DesignPartner' -and -not $c1.syncAdminsPermissions)
# S2 -- single, community, github, Core (community license)
$c2 = Resolve-PimScenarioContext -Scenario 'S2'
T 'S2 -> updateSource=git-pull, edition=Core (Community), ringGated=$false' `
    ($c2.updateSourceProfile -eq 'git-pull' -and $c2.activeEdition -eq 'Core' -and -not $c2.ringGated -and $c2.distributionEdition -eq 'community')
# S3 -- MSP master, internal, msp config variant, Pro-DesignPartner
$c3 = Resolve-PimScenarioContext -Scenario 'S3'
T 'S3 -> configVariant=msp, updateSource=sync-automateit, edition=Pro-DesignPartner, no admin sync (master)' `
    ($c3.configVariant -eq 'msp' -and $c3.updateSourceProfile -eq 'sync-automateit' -and $c3.activeEdition -eq 'Pro-DesignPartner' -and -not $c3.syncAdminsPermissions)
# S4 -- MSP master, community, github, Pro (paid) -- master features need Pro
$c4 = Resolve-PimScenarioContext -Scenario 'S4'
T 'S4 -> configVariant=msp, updateSource=git-pull, edition=Pro (paid for master features)' `
    ($c4.configVariant -eq 'msp' -and $c4.updateSourceProfile -eq 'git-pull' -and $c4.activeEdition -eq 'Pro' -and $c4.grantBasis -eq 'paid')
# S5 -- managed, CENTRAL hosted, multi-tenant SPN, from-master ring-gated, admin sync
$c5 = Resolve-PimScenarioContext -Scenario 'S5'
T 'S5 -> central-msp hosting, multi-tenant-spn, from-master+ringGated, syncs admins+permissions' `
    ($c5.hostingLocation -eq 'central-msp' -and $c5.spnModel -eq 'multi-tenant-spn' -and $c5.updateSourceProfile -eq 'from-master' -and $c5.ringGated -and $c5.syncAdminsPermissions -and $c5.syncFileLocation -eq 'central-msp')
# S6 -- managed, LOCAL hosted, local SPN, from-master ring-gated, admin sync, local sync files
$c6 = Resolve-PimScenarioContext -Scenario 'S6'
T 'S6 -> local-slave hosting, local-spn, from-master+ringGated, syncs admins+permissions, local sync files' `
    ($c6.hostingLocation -eq 'local-slave' -and $c6.spnModel -eq 'local-spn' -and $c6.updateSourceProfile -eq 'from-master' -and $c6.ringGated -and $c6.syncAdminsPermissions -and $c6.syncFileLocation -eq 'local-slave')
# Only managed scenarios sync admins/permissions + ring-gate
$mgd = @($catalog | Where-Object { $_.role -eq 'msp-managed' } | ForEach-Object { "$($_.id)" })
T 'exactly S5+S6 are the managed (ring-gated, admin-syncing) scenarios' (($mgd -join ',') -eq 'S5,S6')

Write-Host "`n== 5. ACTIVE SCENARIO + APPLY ==" -ForegroundColor Cyan
Reset-Store
T 'Get-PimActiveScenario defaults to S1 when nothing is set' ((Get-PimActiveScenario).id -eq 'S1')
T 'explicit override wins' ((Get-PimActiveScenario -Override 'S5').id -eq 'S5')
# persisted bare id
$script:__store['Scenario'] = 'S6'
T 'persisted bare id (S6) is read from the store' ((Get-PimActiveScenario).id -eq 'S6')
# persisted JSON shape
$script:__store['Scenario'] = '{"scenario":"S3"}'
T 'persisted JSON shape {"scenario":"S3"} is read' ((Get-PimActiveScenario).id -eq 'S3')
# unknown id falls back to default S1 (fail-safe)
$script:__store['Scenario'] = 'S99'
T 'unknown persisted id falls back to S1 (fail-safe)' ((Get-PimActiveScenario).id -eq 'S1')
# apply sets the existing globals
Reset-Store
$applied = Set-PimScenarioContext -Scenario 'S5' -Quiet
T 'Set-PimScenarioContext sets PIM_ConfigVariant=msp' ($global:PIM_ConfigVariant -eq 'msp')
T 'Set-PimScenarioContext sets PIM_ScenarioRingGated=$true for managed' ($global:PIM_ScenarioRingGated -eq $true)
T 'Set-PimScenarioContext sets PIM_ActiveScenario=S5' ($global:PIM_ActiveScenario -eq 'S5')
T 'Set-PimScenarioContext sets PIM_DistributionEdition' ("$($global:PIM_DistributionEdition)".Trim().Length -gt 0)
T 'Set-PimScenarioContext returns the resolution it applied' ($applied.id -eq 'S5')
Reset-Store

Write-Host ""
Write-Host ("==== Scenario-profile test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
