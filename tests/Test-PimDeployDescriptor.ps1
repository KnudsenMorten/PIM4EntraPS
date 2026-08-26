#Requires -Version 5.1
<#
  BUG-67 regression tests: the deploy's HOSTING flavour comes from the ENVIRONMENT DESCRIPTOR, not
  from the MSP topology.

  Offline. The orchestrator is driven with an INJECTED step runner (-StepRunner), which is its own
  built-in test seam -- so no Azure call is made, nothing is created, and the run is a pure exercise
  of the decision under test.

  The bug being guarded: "local" meant both "in the customer's own tenant" (MSP topology) and "on a
  VM with a local build" (hosting flavour). An S6 managed tenant running on Container Apps -- the
  normal case in the estate -- resolved to hosted=False and would have had INFRA sent to
  Setup-PimVM.ps1 instead of Setup-PimContainers.ps1.
#>
param()
$ErrorActionPreference = 'Stop'

$sol  = Split-Path -Parent $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $sol)
$orch = Join-Path $sol 'tools\setup\Invoke-PimDeployAll.ps1'

$script:pass = 0; $script:fail = 0
function T { param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red } }

function New-Descriptor { param([string]$Json)
    $p = Join-Path ([IO.Path]::GetTempPath()) ("pim-desc-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    [IO.File]::WriteAllText($p, $Json, [Text.UTF8Encoding]::new($false)); return $p }

# A no-op runner: every step "succeeds" without doing anything, so we can read the PLAN the
# orchestrator built rather than its side effects.
$runner = { param($Key, $Ctx) @{ ok = $true; ran = $true; detail = "stub:$Key" } }

# A descriptor satisfying PIM's REAL contract, with ACA declared.
$acaJson = @'
{ "schema": 1, "location": "swedencentral",
  "solutions": { "PIM4EntraPS": { "provides": {
      "azure-sql":                  { "mode": "provision", "server": "sql-x.database.windows.net", "database": "PimPlatform" },
      "azure-container-registry":   { "mode": "provision", "name": "acrx" },
      "container-apps-environment": { "mode": "provision", "name": "cae-pim-ext" },
      "entra-app-registration":     { "mode": "existing",  "appId": "11111111-1111-1111-1111-111111111111" },
      "key-vault":                  { "mode": "provision", "name": "kv-pim-x", "isolation": "dedicated" },
      "msp-master-template-store":  { "mode": "existing",  "name": "https://x.blob.core.windows.net/baseline" } } } } }
'@
# A genuinely VM-hosted environment: no container-apps-environment. Note PIM's OWN contract makes
# `infra` require ACA, so a VM environment must also BLOCK the infra capability -- which the
# contract explicitly permits (infra is optional, precisely so a differently-hosted install works).
# Demanding ACA of a VM install would be the contract contradicting itself, not a descriptor error.
$vmJson = $acaJson -replace '"container-apps-environment":\s*\{[^}]*\},', ''

# Write-Host goes to the INFORMATION stream, so `2>&1` alone captures none of it and every
# assertion below would fail against an empty string -- a test that passes or fails for reasons
# unrelated to the code. `*>&1` merges every stream.
# Splat a HASHTABLE, not an array -- `& $script @array` binds POSITIONALLY, so '-Scenario' arrives
# as the value of the first positional parameter ($Source) and fails its ValidateSet.
function Invoke-Orch { param([string]$Desc, [switch]$SkipAppReg)
    $a = @{
        Scenario       = 'S6'
        StepRunner     = $runner
        TenantId       = '00000000-0000-0000-0000-000000000000'
        SubscriptionId = '00000000-0000-0000-0000-000000000001'
        SkipVerify     = $true
    }
    if ($Desc)        { $a['Descriptor'] = $Desc }
    if ($SkipAppReg)  { $a['SkipAppReg'] = $true }
    & $orch @a *>&1 | Out-String
}

Write-Host "`n== 1. THE BUG: S6 + ACA must resolve to HOSTED ==" -ForegroundColor Cyan
$out = Invoke-Orch -SkipAppReg -Desc (New-Descriptor $acaJson)
T 'the run completes' ($out -match 'DEPLOY-ALL PLAN')
T '🔴 S6 + a declared ACA environment resolves to hosted=True' ($out -match 'hosted=True')
T '  ...and says the descriptor overrode the topology-inferred value' ($out -match '\[descriptor\] hosting: False -> True')
T '  ...citing BUG-67 so the reason is findable' ($out -match 'BUG-67')
# 🪤 The header and the PLAN must agree. They did not at first: the orchestrator corrected its own
# $hosted while Get-PimDeployAllPlan re-derived a stale one, so the plan gated hostedOnly steps on
# the value the fix was meant to replace. A fix that only half-lands is worse than none.
T '🔒 the PLAN agrees with the header (the override reaches the pure core too)' ($out -match 'PLAN \(WHATIF; hosted=True\)')

Write-Host "`n== 2. NO ACA DECLARED => the VM path is still correct ==" -ForegroundColor Cyan
$outVm = Invoke-Orch -SkipAppReg -Desc (New-Descriptor $vmJson)
T 'an environment that declares no ACA stays hosted=False' ($outVm -match 'hosted=False')
T '  ...silently, because nothing was overridden' (-not ($outVm -match '\[descriptor\] hosting:'))

Write-Host "`n== 3. 🔒 NON-BREAKING: no descriptor => unchanged behaviour ==" -ForegroundColor Cyan
# ~30 environments deployed before the descriptor existed must behave exactly as they did.
$outNone = Invoke-Orch -SkipAppReg
T 'without -Descriptor the inferred value stands (S6 -> hosted=False)' ($outNone -match 'hosted=False')
T '  ...and no descriptor machinery runs at all' (-not ($outNone -match '\[descriptor\]'))

Write-Host "`n== 4. THE DESCRIPTOR IS A GATE, NOT JUST A SOURCE OF VALUES ==" -ForegroundColor Cyan
# An unresolved dependency must stop the deploy HERE, where the message is actionable -- not three
# scripts deep once infra already exists.
$incomplete = New-Descriptor '{ "schema": 1, "solutions": { "PIM4EntraPS": { "provides": { "azure-sql": { "mode": "provision", "server": "s" } } } } }'
$failed = $false
try {
    & $orch -Scenario S6 -Descriptor $incomplete -StepRunner $runner `
        -TenantId '00000000-0000-0000-0000-000000000000' -SubscriptionId '00000000-0000-0000-0000-000000000001' `
        -SkipAppReg -SkipVerify 2>&1 | Out-Null
} catch { $failed = $true }
T 'an INCOMPLETE descriptor REFUSES the deploy before anything is created' $failed

$missingFile = $false
try {
    & $orch -Scenario S6 -Descriptor (Join-Path ([IO.Path]::GetTempPath()) 'no-such-descriptor.json') -StepRunner $runner `
        -TenantId '00000000-0000-0000-0000-000000000000' -SubscriptionId '00000000-0000-0000-0000-000000000001' `
        -SkipAppReg -SkipVerify 2>&1 | Out-Null
} catch { $missingFile = $true }
T 'a -Descriptor pointing at nothing REFUSES (never silently falls back)' $missingFile

Write-Host "`n== 5. THE CLI RULE HOLDS (DEPLOY-2 §4) ==" -ForegroundColor Cyan
# The descriptor's whole value is being the single source of truth. A resource-naming parameter
# added here would re-open the second configuration surface it exists to close.
$src = [IO.File]::ReadAllText($orch)
$paramBlock = [regex]::Match($src, '(?s)\[CmdletBinding.*?\n\)').Value
T '-Descriptor names WHICH file (allowed: which descriptor + what mode)' ($paramBlock -match '\$Descriptor')
T '  ...and the rule is documented at the parameter, where it will be read' ($paramBlock -match 'never an infrastructure value')

Write-Host "`n==== deploy descriptor (BUG-67): $($script:pass) passed, $($script:fail) failed ====" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
