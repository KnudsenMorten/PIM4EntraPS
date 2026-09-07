<#
  TEST-32 -- offline cover for the estate TOPOLOGY CLAIM.

  The hazard: a torn-down tenant could not make the estate matrix fail. HOGYM's hosting was removed
  on 2026-08-26 and `Run-PimMatrixEstate.ps1` kept reporting a green "managed slave verified",
  because the driver keeps desired state in LOCAL SQL Express and reads the engine identity from the
  tenant's OWN vault -- both outlive a teardown, so nothing it checked could notice. The green was
  true about the DIRECTORY and false about the CLAIM.

  TEST-32's own write-up named the missing piece exactly: *"nothing machine-readable states that
  today."* These assertions cover the thing that now does -- the declaration, the pure verdict, and
  the driver's refusal to run an environment whose claim it cannot confirm.

  All OFFLINE: the declaration is read from disk, the verifier is pure, and the driver is read as
  text. No az, no tenant, no network.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
$live = Join-Path $root 'tests\live'
. (Join-Path $live '_PimEstateTopology.ps1')

Write-Host "`n== 1. THE CLAIM IS DECLARED AT ALL (this is the whole finding) ==" -ForegroundColor Cyan
$claims = @(Get-PimEstateTopologyClaims)
T 'the estate declares a topology claim per environment' (@($claims).Count -ge 3)
T '  ...and every claim names its topology and says WHY that is what it is' (
    @($claims | Where-Object { "$($_.topology)".Trim() -and "$($_.why)".Trim() }).Count -eq @($claims).Count)

# 🔒 The driver's DEFAULT environment list and the declaration must not drift apart: an
# environment that runs without a claim is exactly the pre-TEST-32 state for that tenant.
$drvSrc = Get-Content -Raw -LiteralPath (Join-Path $live 'Run-PimMatrixEstate.ps1')
$defaults = @()
if ($drvSrc -match "(?s)\[string\[\]\]\`$Environments\s*=\s*@\(([^)]*)\)") {
    $defaults = @([regex]::Matches($Matches[1], "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
}
T 'the driver default environment list was parsed (a guard that finds nothing proves nothing)' (@($defaults).Count -ge 3)
$undeclared = @($defaults | Where-Object { $d = $_; -not (@($claims) | Where-Object { "$($_.env)" -eq $d }) })
T '  ...and EVERY default environment has a declared claim' (@($undeclared).Count -eq 0)

Write-Host "`n== 2. NOT OBSERVED IS NOT SATISFIED (the HOGYM case) ==" -ForegroundColor Cyan
$slave = @($claims | Where-Object { "$($_.topology)" -eq 'msp-slave' })[0]
T 'the managed-slave claim requires a live Azure stack' ([bool]$slave.requiresAzureStack)
# The exact HOGYM shape: directory fine, vault fine, cert fine -- stack gone.
$vTorn = Test-PimEstateTopologyClaim -Claim $slave -Observed @{ azureStackPresent = $false; isManaged = $true }
T 'A TORN-DOWN slave FAILS its claim' (-not $vTorn.ok)
T '  ...and the failure says the tenant USED TO BE that topology, not merely "failed"' (
    (@($vTorn.failures) -join ' ') -match 'USED TO BE')
# 🔒 The distinction that makes this a guard rather than a formality.
$vUnknown = Test-PimEstateTopologyClaim -Claim $slave -Observed @{ azureStackPresent = $null; isManaged = $true }
T 'an UNOBSERVED stack also fails -- "we did not look" is not "we looked and it is fine"' (-not $vUnknown.ok)
T '  ...and says so explicitly, so the reason is not confused with a real teardown' (
    (@($vUnknown.failures) -join ' ') -match 'NOT OBSERVED')
$vOk = Test-PimEstateTopologyClaim -Claim $slave -Observed @{ azureStackPresent = $true; isManaged = $true }
T 'CONTROL: a live managed slave passes (or the checks above pass for the wrong reason)' ($vOk.ok)
T '  ...and reports WHICH facts it checked, so a passing claim is auditable too' (@($vOk.checked) -contains 'azureStackPresent')

Write-Host "`n== 3. THE OTHER TOPOLOGIES ==" -ForegroundColor Cyan
$standalone = @($claims | Where-Object { "$($_.topology)" -eq 'standalone' })[0]
# The asymmetry is deliberate and worth pinning: a standalone case needs no hosted stack, so
# demanding one would fail an environment that is genuinely fine.
T 'the standalone claim does NOT require an Azure stack (it exercises the directory only)' (-not [bool]$standalone.requiresAzureStack)
$vStand = Test-PimEstateTopologyClaim -Claim $standalone -Observed @{ isManaged = $false }
T '  ...and passes when it has no master' ($vStand.ok)
$vStandBad = Test-PimEstateTopologyClaim -Claim $standalone -Observed @{ isManaged = $true }
T '  ...but FAILS once it acquires one (it has stopped being the standalone case)' (
    -not $vStandBad.ok -and (@($vStandBad.failures) -join ' ') -match 'standalone')
$master = @($claims | Where-Object { "$($_.topology)" -eq 'msp-master' })[0]
$vMaster = Test-PimEstateTopologyClaim -Claim $master -Observed @{ azureStackPresent = $true; publishesBaseline = $false }
T 'a master that publishes NO baseline fails its defining act' (-not $vMaster.ok)

Write-Host "`n== 4. AN UNFALSIFIABLE CLAIM IS NOT A PASSING CLAIM ==" -ForegroundColor Cyan
# 🪤 The failure mode this guard could most easily acquire: someone adds an environment with a
# topology name and no facts, and it passes forever. That restores "the run came back green" as the
# only evidence, which TEST-32 says does not answer the question.
$empty = [pscustomobject]@{ env = 'test-nothing'; topology = 'msp-slave'; why = 'x' }
$vEmpty = Test-PimEstateTopologyClaim -Claim $empty -Observed @{}
T 'a claim with NO checkable fact FAILS rather than passing vacuously' (-not $vEmpty.ok)
T '  ...naming what is missing, so the fix is obvious' ((@($vEmpty.failures) -join ' ') -match 'requiresAzureStack')

Write-Host "`n== 5. THE DRIVER ACTUALLY ENFORCES IT ==" -ForegroundColor Cyan
# A verifier nobody calls is the same class of defect as the gates BUG-29/78/79 were about.
$drvCode = (($drvSrc -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
T 'the driver dot-sources the topology verifier' ($drvCode -match '_PimEstateTopology\.ps1')
T '  ...loads the declared claims' ($drvCode -match 'Get-PimEstateTopologyClaims')
T '  ...REFUSES an environment that has no declared claim' ($drvCode -match 'TOPOLOGY CLAIM MISSING')
# 🪤 ASSERT THE ASSIGNMENT, NOT THE NAME. The first version matched the bare function name, so
# stubbing the call and leaving `# Test-PimEstateTopologyClaim` as a TRAILING comment still
# satisfied it -- the negative run reported 23/0 against a driver that no longer verified
# anything. $drvCode strips FULL-LINE comments; a trailing one survives. Matching the assignment
# form is what makes the assert about the CALL rather than about the word appearing somewhere.
T '  ...calls the verdict per environment, as an assignment (not merely mentions its name)' (
    $drvCode -match '\$verdict\s*=\s*Test-PimEstateTopologyClaim')
T '  ...and a failed claim STOPS that environment instead of running it' (
    $drvCode -match '(?s)TOPOLOGY CLAIM FAILED.{0,400}?continue')
# 🔒 The probe must reach the SUBSCRIPTION -- everything else in the driver survived the teardown.
T '  ...and the probe reaches the tenant SUBSCRIPTION, which is what a teardown removes' (
    $drvCode -match 'Set-AzContext' -and $drvCode -match 'Microsoft\.App/containerApps')

Write-Host ""
Write-Host ("==== Estate topology (TEST-32): {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
