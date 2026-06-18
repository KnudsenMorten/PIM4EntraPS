#Requires -Version 5.1
<#
.SYNOPSIS
    Feature-customization + license framework classification test (REQUIREMENTS
    s29 + s30). The test/release GATE for the feature catalog: every entry is
    classified, every advanced feature has a working gate, and a disabled/unlicensed
    advanced feature is INERT (the engine + jobs no-op -- no writes, no sends).

.DESCRIPTION
    All OFFLINE (no live tenant, no server boot, no real send). Layers:

      1. CLASSIFICATION -- every catalog entry declares key + label + group +
         tier(core|advanced) + license(free|pro) + defaultEnabled + dependsOn;
         advanced features default OFF; dependsOn keys all exist; the real
         advanced capabilities are present + classified.

      2. PURE GATES -- Test-PimFeatureEnabled / Licensed / Available over the real
         shared lib (PIM-FeatureCatalog.ps1) with an in-memory store stub: a kill
         switch flips a feature off; a Pro feature is unlicensed under Core and
         licensed under Pro / Pro-DesignPartner; an unknown key is fail-safe off;
         core is always available; dependency issues are surfaced.

      3. ENGINE INERTNESS -- a gated provider scope (Invoke-PimEngineScope) NO-OPs
         when its feature is disabled: GetDesired/GetLive are NEVER called, the diff
         is empty, no ApplyCreate/Update/Remove fires (no writes). When enabled, the
         provider runs normally.

      4. JOB INERTNESS -- a scheduled job whose feature is disabled NO-OPs at the
         Invoke-PimScheduledJob dispatch: the handler is NEVER invoked (no sends).

      5. EMAIL KILL SWITCH -- Send-PimNotifyMail is a no-op when the email feature
         is disabled OR $global:PIM_MailKillSwitch is set; the allowlist drops a
         recipient not on it. No real Graph send (mocked Invoke-PimGraph asserts it
         is never called when gated).

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-License.ps1')
. (Join-Path $root 'engine\_shared\PIM-FeatureCatalog.ps1')

# ---- in-memory settings store stub (drives Get-PimFeatureStoreValue path 2) -----
$script:__store = @{}
function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
function Set-PimSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) $script:__store[$Name] = $Value }
function Reset-Store { $script:__store = @{}; $global:PIM_NamingConventions = $null; $global:PIM_EngineSqlCs = $null; $global:PIM_SqlConnectionString = $null }
Reset-Store

Write-Host "`n== 1. CLASSIFICATION ==" -ForegroundColor Cyan
$catalog = Get-PimFeatureCatalog
T 'catalog is non-empty' (@($catalog).Count -gt 0)

$keys = @{}
$allClassified = $true
foreach ($f in $catalog) {
    if (-not "$($f.key)".Trim())   { $allClassified = $false }
    if (-not "$($f.label)".Trim()) { $allClassified = $false }
    if (-not "$($f.group)".Trim()) { $allClassified = $false }
    if ("$($f.tier)" -notin @('core','advanced'))   { $allClassified = $false }
    if ("$($f.license)" -notin @('free','pro'))      { $allClassified = $false }
    if ($keys.ContainsKey("$($f.key)")) { $allClassified = $false }   # unique
    $keys["$($f.key)"] = $f
}
T 'every entry declares key+label+group+tier+license (unique keys)' $allClassified

# advanced features default OFF (opt-in)
$advDefaultOff = $true
foreach ($f in $catalog) { if ("$($f.tier)" -eq 'advanced' -and [bool]$f.defaultEnabled) { $advDefaultOff = $false } }
T 'every advanced feature defaults OFF (opt-in)' $advDefaultOff

# core features are free + (implicitly) on
$coreFree = $true
foreach ($f in $catalog) { if ("$($f.tier)" -eq 'core' -and "$($f.license)" -ne 'free') { $coreFree = $false } }
T 'every core feature is license=free' $coreFree

# dependsOn keys all exist
$depsOk = $true
foreach ($f in $catalog) { foreach ($d in @($f.dependsOn)) { if (-not $keys.ContainsKey("$d")) { $depsOk = $false } } }
T 'every dependsOn references an existing feature key' $depsOk

# the real advanced capabilities are present + classified
foreach ($expect in @('discovery.sweep','alerting.email','alerting.webhook','connectors.workload','connectors.powerbi','connectors.exo','msp.downlink','scheduler.jobs')) {
    T "advanced capability '$expect' is in the catalog" ($keys.ContainsKey($expect) -and "$($keys[$expect].tier)" -eq 'advanced')
}
# the Pro-licensed advanced capabilities
foreach ($pro in @('connectors.workload','connectors.powerbi','connectors.exo','msp.downlink')) {
    T "'$pro' is license=pro" ("$($keys[$pro].license)" -eq 'pro')
}

Write-Host "`n== 2. PURE GATES ==" -ForegroundColor Cyan
Reset-Store
# default: an advanced free feature is enabled? -> default OFF, so NOT enabled
T 'advanced feature is DISABLED by default (kill switch off)' (-not (Test-PimFeatureEnabled -Key 'discovery.sweep'))
# core is always enabled + available
T 'core feature is always enabled' (Test-PimFeatureEnabled -Key 'engine.reconcile')
T 'core feature is always available' (Test-PimFeatureAvailable -Key 'engine.reconcile' -Quiet)
# unknown key is fail-safe off
T 'unknown feature key is fail-safe (Available=false)' (-not (Test-PimFeatureAvailable -Key 'does.not.exist' -Quiet))

# turn discovery.sweep ON via the store
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'discovery.sweep' = $true } })
T 'persisted override enables a feature' (Test-PimFeatureEnabled -Key 'discovery.sweep')
T 'enabled free feature is available' (Test-PimFeatureAvailable -Key 'discovery.sweep' -Quiet)

# license gate: a Pro feature under Core is NOT licensed; under Pro it is
Reset-Store
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'connectors.workload' = $true } })   # enabled but...
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Core' })
T 'Pro feature is enabled but NOT licensed under Core' ((Test-PimFeatureEnabled -Key 'connectors.workload') -and -not (Test-PimFeatureLicensed -Key 'connectors.workload'))
T 'Pro feature is NOT available under Core (enabled but unlicensed)' (-not (Test-PimFeatureAvailable -Key 'connectors.workload' -Quiet))
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Pro' })
T 'Pro feature IS licensed + available under Pro' ((Test-PimFeatureLicensed -Key 'connectors.workload') -and (Test-PimFeatureAvailable -Key 'connectors.workload' -Quiet))
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Pro-DesignPartner' })
T 'Pro feature IS available under Pro-DesignPartner too' (Test-PimFeatureAvailable -Key 'connectors.workload' -Quiet)

# -Edition override (what-if for the GUI preview)
T 'Test-PimFeatureLicensed honours -Edition override' ((Test-PimFeatureLicensed -Key 'connectors.workload' -Edition 'Pro') -and -not (Test-PimFeatureLicensed -Key 'connectors.workload' -Edition 'Core'))

# dependency issue surfaced: enable connectors.powerbi (needs discovery.sweep) but leave discovery off
Reset-Store
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'connectors.powerbi' = $true } })
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Pro' })
$issues = Get-PimFeatureDependencyIssues
T 'dependency issue surfaced (powerbi enabled, discovery.sweep not available)' (@($issues | Where-Object { $_.feature -eq 'connectors.powerbi' -and $_.dependsOn -eq 'discovery.sweep' }).Count -ge 1)

Write-Host "`n== 3. ENGINE INERTNESS (gated provider no-ops) ==" -ForegroundColor Cyan
Reset-Store
. (Join-Path $root 'engine\_shared\PIM-EngineCore.ps1')

# a fake provider that maps to an advanced feature; record whether its closures fire.
$script:__desiredCalled = $false; $script:__createCalled = $false
function New-FakeGatedProvider {
    @{
        scope='FakeGated'; entity='Fake-Entity'; feature='connectors.workload'
        GetDesired = { param($ctx) $script:__desiredCalled = $true; @([pscustomobject]@{ key='x'; name='x' }) }
        GetLive    = { param($ctx) @() }
        KeyOf      = { param($i) "$($i.key)" }
        Equal      = { param($a,$b) $true }
        ApplyCreate= { param($i,$ctx) $script:__createCalled = $true }
    }
}
function Get-PimEngineProvider { param($Scope) New-FakeGatedProvider }   # override resolver for the test

# feature DISABLED -> scope no-ops: desired never resolved, no create fires
Reset-Store
$r1 = Invoke-PimEngineScope -Scope 'FakeGated' -Mode Delta -WhatIf
T 'disabled provider scope returns ok with skippedFeature' ($r1.ok -and "$($r1.skippedFeature)" -eq 'connectors.workload')
T 'disabled provider: GetDesired NEVER called (no read)' (-not $script:__desiredCalled)
T 'disabled provider: ApplyCreate NEVER called (no write)' (-not $script:__createCalled)

# feature ENABLED + licensed -> scope runs (GetDesired called). Use WhatIf so no real apply.
$script:__desiredCalled = $false; $script:__createCalled = $false
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'connectors.workload' = $true } })
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Pro' })
$r2 = Invoke-PimEngineScope -Scope 'FakeGated' -Mode Delta -WhatIf
T 'enabled+licensed provider scope RUNS (GetDesired called)' ($script:__desiredCalled)
T 'enabled provider plan (WhatIf) makes no real write' (-not $script:__createCalled)

# feature ENABLED but UNLICENSED (Core) -> still inert
$script:__desiredCalled = $false
Set-PimSetting -Name 'Edition' -Value ([ordered]@{ edition = 'Core' })
$r3 = Invoke-PimEngineScope -Scope 'FakeGated' -Mode Delta -WhatIf
T 'enabled-but-unlicensed provider scope NO-OPs (GetDesired not called)' (-not $script:__desiredCalled -and "$($r3.skippedFeature)" -eq 'connectors.workload')

Write-Host "`n== 4. JOB INERTNESS (gated scheduled job no-ops) ==" -ForegroundColor Cyan
Reset-Store
. (Join-Path $root 'engine\_shared\PIM-Scheduler.ps1')
$script:__jobRan = $false
Register-PimJobHandler -Type 'discovery' -Handler { param($job,$now,$whatIf) $script:__jobRan = $true; [pscustomobject]@{ ran=$true; detail='ran' } }
# scheduler.jobs default OFF -> ALL jobs no-op
$jr1 = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='disc'; type='discovery' }) -WhatIf
T 'job no-ops when scheduler.jobs disabled (master switch)' (-not $script:__jobRan -and "$($jr1.skippedFeature)" -eq 'scheduler.jobs')
# enable scheduler.jobs but leave discovery.sweep OFF -> the discovery job still no-ops
$script:__jobRan = $false
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'scheduler.jobs' = $true } })
$jr2 = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='disc'; type='discovery' }) -WhatIf
T 'discovery job no-ops when discovery.sweep disabled (per-type gate)' (-not $script:__jobRan -and "$($jr2.skippedFeature)" -eq 'discovery.sweep')
# enable both -> the job runs
$script:__jobRan = $false
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'scheduler.jobs' = $true; 'discovery.sweep' = $true } })
$jr3 = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='disc'; type='discovery' }) -WhatIf
T 'job RUNS when both scheduler.jobs + discovery.sweep enabled' ($script:__jobRan -and $jr3.ok)

Write-Host "`n== 5. EMAIL KILL SWITCH + allowlist (no real send) ==" -ForegroundColor Cyan
Reset-Store
. (Join-Path $root 'engine\_shared\PIM-Notify.ps1')
$script:__graphCalled = $false
function Invoke-PimGraph { param($Method,$Path,$Body,[switch]$Beta,[switch]$All) $script:__graphCalled = $true; @{} }
$global:PIM_MailSender = 'sender@example.test'
$global:PIM_MailTemplateDir = (Join-Path $root 'templates\mail')   # use the real templates dir so a template exists

# email feature DISABLED (default) -> no send, Graph never called
$res1 = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{ } -Recipient 'a@example.test'
T 'email feature disabled => Send-PimNotifyMail is a no-op' (-not $res1.sent -and "$($res1.reason)" -eq 'email feature disabled')
T 'email feature disabled => Graph send NEVER called' (-not $script:__graphCalled)

# enable email feature, but set the GLOBAL kill switch -> still no send
Set-PimSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = [ordered]@{ 'alerting.email' = $true } })
$global:PIM_MailKillSwitch = $true
$script:__graphCalled = $false
$res2 = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{ } -Recipient 'a@example.test'
T 'global email kill switch => no-op even when feature enabled' (-not $res2.sent -and "$($res2.reason)" -eq 'email kill switch on' -and -not $script:__graphCalled)

# clear kill switch, set an allowlist that excludes the recipient -> dropped
$global:PIM_MailKillSwitch = $false
$global:PIM_MailAllowlist = @('allowed@example.test')
$script:__graphCalled = $false
$res3 = Send-PimNotifyMail -Type 'daily-summary' -Tokens @{ } -Recipient 'blocked@example.test'
T 'allowlist drops a recipient not on it (no send)' (-not $res3.sent -and "$($res3.reason)" -eq 'recipient not on allowlist' -and -not $script:__graphCalled)

# cleanup globals
$global:PIM_MailKillSwitch = $null; $global:PIM_MailAllowlist = $null; $global:PIM_MailSender = $null; Remove-Variable -Name PIM_MailTemplateDir -Scope Global -ErrorAction SilentlyContinue

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
