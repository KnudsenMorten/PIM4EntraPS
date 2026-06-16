#Requires -Version 5.1
<#
.SYNOPSIS
    Operational-policy Settings config surface (REQUIREMENTS [M7]) -- expiry-policy
    defaults, MFA-on-activation toggle, connection-sanity config. Proves every knob
    persists + reads back identically through the REAL store wrappers
    (Get-/Set-PimOperationalPolicy), defaults are correct, and an invalid value is
    rejected/clamped (never silently dropped).

.DESCRIPTION
    Three layers, all OFFLINE (no live tenant, no server boot):

      1. PURE normalize/validate/clamp over the REAL shared lib
         (engine/_shared/PIM-OperationalPolicy.ps1): defaults; ISO duration
         catalog validation; out-of-range clamping; the default-<=-max invariant;
         duration-to-minutes parsing.

      2. GUI -> STORE -> READ round-trip through the REAL Manager wrappers
         (Get-/Set-PimOperationalPolicy extracted from Open-PimManager.ps1) over an
         in-memory store stub = the SAME Get-/Set-PimManagerSetting chain the engine
         + scheduled jobs read pim.Settings through. Proves a saved GUI value reads
         back identically (so GUI state == runtime behavior).

      3. STATIC GUI / SERVER wiring (no dead view): the Settings tab renders the
         operational-policy card and the server routes GET/PUT
         /api/settings/operational-policy with a SuperAdmin gate on the write.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root    = Split-Path -Parent $PSScriptRoot           # ...\PIM4EntraPS
$lib     = Join-Path $root 'engine\_shared\PIM-OperationalPolicy.ps1'
$srvPath = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$htmlPath= Join-Path $root 'tools\pim-manager\pim-manager.html'
T 'PIM-OperationalPolicy.ps1 present' (Test-Path -LiteralPath $lib)
T 'Open-PimManager.ps1 present'       (Test-Path -LiteralPath $srvPath)
T 'pim-manager.html present'          (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

Set-StrictMode -Off
. $lib

# ===========================================================================
# Layer 1 -- PURE normalize / validate / clamp (real shared lib)
# ===========================================================================
Write-Host "`n-- Layer 1: pure normalize/validate/clamp --" -ForegroundColor Cyan

# Defaults on an empty store.
$d = ConvertTo-PimNormalizedOperationalPolicy -Raw $null
T 'default defaultActivationDuration = PT8H' ("$($d.value.expiry.defaultActivationDuration)" -eq 'PT8H')
T 'default maxActivationDuration = P1D'      ("$($d.value.expiry.maxActivationDuration)" -eq 'P1D')
T 'default maxEligibilityDuration = P365D'   ("$($d.value.expiry.maxEligibilityDuration)" -eq 'P365D')
T 'default mfaOnActivation = $true (secure default)' ([bool]$d.value.mfaOnActivation -eq $true)
T 'default sqlTimeoutSeconds = 15'           ([int]$d.value.connectionSanity.sqlTimeoutSeconds -eq 15)
T 'default graphTimeoutSeconds = 30'         ([int]$d.value.connectionSanity.graphTimeoutSeconds -eq 30)
T 'default requireSql = $true'               ([bool]$d.value.connectionSanity.requireSql -eq $true)
T 'default requireGraph = $true'             ([bool]$d.value.connectionSanity.requireGraph -eq $true)
T 'no warnings on default'                   (@($d.warnings).Count -eq 0)

# Duration catalog validators.
T 'PT8H is a valid activation duration'      (Test-PimActivationDuration 'PT8H')
T 'P99D is NOT a valid activation duration'  (-not (Test-PimActivationDuration 'P99D'))
T 'P365D is a valid eligibility duration'    (Test-PimEligibilityDuration 'P365D')
T 'PT8H is NOT a valid eligibility duration' (-not (Test-PimEligibilityDuration 'PT8H'))

# Duration-to-minutes parsing (locale-safe, pure).
T 'PT8H = 480 minutes'  ((ConvertTo-PimDurationMinutes 'PT8H') -eq 480)
T 'P1D = 1440 minutes'  ((ConvertTo-PimDurationMinutes 'P1D') -eq 1440)
T 'PT30M = 30 minutes'  ((ConvertTo-PimDurationMinutes 'PT30M') -eq 30)
T 'garbage = 0 minutes' ((ConvertTo-PimDurationMinutes 'nonsense') -eq 0)

# Invalid value is REJECTED (kept default) + a warning surfaced -- never silently dropped.
$bad = ConvertTo-PimNormalizedOperationalPolicy -Raw ([ordered]@{ expiry = [ordered]@{ defaultActivationDuration = 'P99D' } })
T 'invalid duration rejected -> kept default'   ("$($bad.value.expiry.defaultActivationDuration)" -eq 'PT8H')
T 'invalid duration produces a warning'         (@($bad.warnings | Where-Object { $_ -match 'defaultActivationDuration' }).Count -ge 1)

# Out-of-range timeout is CLAMPED + warned (not dropped).
$clamp = ConvertTo-PimNormalizedOperationalPolicy -Raw ([ordered]@{ connectionSanity = [ordered]@{ sqlTimeoutSeconds = 9999; graphTimeoutSeconds = 0 } })
T 'over-range sqlTimeoutSeconds clamped to 300' ([int]$clamp.value.connectionSanity.sqlTimeoutSeconds -eq 300)
T 'under-range graphTimeoutSeconds clamped to 1'([int]$clamp.value.connectionSanity.graphTimeoutSeconds -eq 1)
T 'clamping produces warnings'                  (@($clamp.warnings).Count -ge 2)

# Non-numeric timeout rejected -> kept default + warned.
$nan = ConvertTo-PimNormalizedOperationalPolicy -Raw ([ordered]@{ connectionSanity = [ordered]@{ sqlTimeoutSeconds = 'abc' } })
T 'non-numeric timeout kept default'  ([int]$nan.value.connectionSanity.sqlTimeoutSeconds -eq 15)
T 'non-numeric timeout warned'        (@($nan.warnings | Where-Object { $_ -match 'sqlTimeoutSeconds' }).Count -ge 1)

# default-activation-<=-max invariant: a default longer than max is clamped down.
$inv = ConvertTo-PimNormalizedOperationalPolicy -Raw ([ordered]@{ expiry = [ordered]@{ defaultActivationDuration = 'P3D'; maxActivationDuration = 'PT8H' } })
T 'default > max clamped down to max'  ("$($inv.value.expiry.defaultActivationDuration)" -eq 'PT8H')
T 'default > max produces a warning'   (@($inv.warnings | Where-Object { $_ -match 'exceeds' }).Count -ge 1)

# A fully-valid custom value round-trips unchanged.
$good = ConvertTo-PimNormalizedOperationalPolicy -Raw ([ordered]@{
    expiry = [ordered]@{ defaultActivationDuration = 'PT4H'; maxActivationDuration = 'P2D'; maxEligibilityDuration = 'P90D' }
    mfaOnActivation = $false
    connectionSanity = [ordered]@{ sqlTimeoutSeconds = 20; graphTimeoutSeconds = 45; requireSql = $false; requireGraph = $true }
})
T 'valid custom value preserved (no warnings)' (@($good.warnings).Count -eq 0 -and "$($good.value.expiry.defaultActivationDuration)" -eq 'PT4H' -and [bool]$good.value.mfaOnActivation -eq $false -and [int]$good.value.connectionSanity.sqlTimeoutSeconds -eq 20)

# JSON-string + PSCustomObject shape (the SQL store hands back a JSON-parsed object).
$jsonStr = ([ordered]@{ expiry = [ordered]@{ defaultActivationDuration = 'PT2H' }; mfaOnActivation = $false } | ConvertTo-Json -Depth 8)
$fromJson = ConvertTo-PimNormalizedOperationalPolicy -Raw $jsonStr
T 'JSON-string raw parsed (PT2H read back)'  ("$($fromJson.value.expiry.defaultActivationDuration)" -eq 'PT2H' -and [bool]$fromJson.value.mfaOnActivation -eq $false)
$psObj = $jsonStr | ConvertFrom-Json
$fromObj = ConvertTo-PimNormalizedOperationalPolicy -Raw $psObj
T 'PSCustomObject raw read (PT2H read back)'  ("$($fromObj.value.expiry.defaultActivationDuration)" -eq 'PT2H')

# ===========================================================================
# Layer 2 -- GUI -> STORE -> READ round-trip through the REAL Manager wrappers
# ===========================================================================
Write-Host "`n-- Layer 2: GUI -> store -> read round-trip (real wrappers, in-proc) --" -ForegroundColor Cyan

function Get-FnBody([string]$source, [string]$name) {
    $pat = 'function ' + [regex]::Escape($name) + '\b[\s\S]*?\n\}\r?\n'
    $m = [regex]::Match($source, $pat)
    if (-not $m.Success) { return $null }
    return $m.Value
}
$srv = [System.IO.File]::ReadAllText($srvPath)
$getFn = Get-FnBody $srv 'Get-PimOperationalPolicy'
$setFn = Get-FnBody $srv 'Set-PimOperationalPolicy'
T 'Get-PimOperationalPolicy body extracted' ([bool]$getFn)
T 'Set-PimOperationalPolicy body extracted' ([bool]$setFn)

if ($getFn -and $setFn) {
    # In-memory store = the SAME Get-/Set-PimManagerSetting chain pim.Settings is
    # read/written through (engine + jobs + GUI all read this store).
    $script:__store = @{}
    function Get-PimManagerSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
    function Set-PimManagerSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) $script:__store[$Name] = $Value }

    Invoke-Expression $getFn
    Invoke-Expression $setFn

    # Empty store -> fully-populated defaults (never empty).
    $r0 = Get-PimOperationalPolicy
    T 'empty store reads defaults'           ("$($r0.value.expiry.defaultActivationDuration)" -eq 'PT8H' -and [bool]$r0.value.mfaOnActivation -eq $true)
    T 'GET exposes the duration catalogs'    (@($r0.catalogs.activationDuration).Count -gt 0 -and @($r0.catalogs.eligibilityDuration).Count -gt 0)

    # SAVE a custom policy (the shape the GUI PUTs) ...
    $saved = Set-PimOperationalPolicy -Policy ([ordered]@{
        expiry = [ordered]@{ defaultActivationDuration = 'PT4H'; maxActivationDuration = 'P2D'; maxEligibilityDuration = 'P90D' }
        mfaOnActivation = $false
        connectionSanity = [ordered]@{ sqlTimeoutSeconds = 25; graphTimeoutSeconds = 50; requireSql = $false; requireGraph = $false }
    })
    T 'save returns the persisted value'     ("$($saved.value.expiry.defaultActivationDuration)" -eq 'PT4H')
    # ... and it READS BACK IDENTICALLY through a fresh Get (proves it hit the store).
    $r1 = Get-PimOperationalPolicy
    T 'expiry defaults persist + read back'  ("$($r1.value.expiry.defaultActivationDuration)" -eq 'PT4H' -and "$($r1.value.expiry.maxActivationDuration)" -eq 'P2D' -and "$($r1.value.expiry.maxEligibilityDuration)" -eq 'P90D')
    T 'MFA toggle persists + reads back'     ([bool]$r1.value.mfaOnActivation -eq $false)
    T 'connection-sanity persists + reads back' ([int]$r1.value.connectionSanity.sqlTimeoutSeconds -eq 25 -and [int]$r1.value.connectionSanity.graphTimeoutSeconds -eq 50 -and [bool]$r1.value.connectionSanity.requireSql -eq $false)
    T 'the underlying store key is OperationalPolicy' ($script:__store.ContainsKey('OperationalPolicy'))

    # SAVE an invalid value -> store holds the CLAMPED/normalized value, not garbage.
    [void](Set-PimOperationalPolicy -Policy ([ordered]@{ expiry = [ordered]@{ defaultActivationDuration = 'P99D' }; connectionSanity = [ordered]@{ sqlTimeoutSeconds = 9999 } }))
    $r2 = Get-PimOperationalPolicy
    T 'invalid save -> store holds normalized (no garbage)' ("$($r2.value.expiry.defaultActivationDuration)" -eq 'PT8H' -and [int]$r2.value.connectionSanity.sqlTimeoutSeconds -eq 300)
}

# ===========================================================================
# Layer 3 -- STATIC GUI / SERVER wiring (no dead view)
# ===========================================================================
Write-Host "`n-- Layer 3: GUI + server wiring (static) --" -ForegroundColor Cyan
$html = [System.IO.File]::ReadAllText($htmlPath)
T 'server dot-sources PIM-OperationalPolicy.ps1' ($srv -match 'PIM-OperationalPolicy\.ps1')
T 'settings bundle includes operationalPolicy'   ($srv -match 'operationalPolicy\s*=\s*\(Get-PimOperationalPolicy\)')
T 'server handles GET /api/settings/operational-policy'  ($srv -match "\`$path -eq '/api/settings/operational-policy' -and \`$method -eq 'GET'")
T 'server handles PUT /api/settings/operational-policy'  ($srv -match "\`$path -eq '/api/settings/operational-policy' -and \`$method -eq 'PUT'")
T 'PUT is SuperAdmin-gated'                       ($srv -match "SuperAdmin role required to edit operational policy")
T 'GUI renders the operational-policy card'       ($html -match 'renderOpPolicyCard\(' -and $html -match 'id="setOpPolicyBody"')
T 'GUI GETs /api/settings/operational-policy'     ($html -match "api\('GET',\s*'/api/settings/operational-policy'")
T 'GUI PUTs /api/settings/operational-policy'     ($html -match "api\('PUT',\s*'/api/settings/operational-policy'")
T 'GUI surfaces normalizer warnings'              ($html -match 'p\.warnings')

# ===========================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green; exit 0 }
else { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
