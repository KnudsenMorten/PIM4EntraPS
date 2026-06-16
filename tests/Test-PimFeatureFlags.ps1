#Requires -Version 5.1
<#
.SYNOPSIS
    Feature-flag registry (gradual rollout) -- "turn any Manager feature on/off in
    Settings so features roll out one by one." Proves the pure catalog + resolver
    apply defaults, a persisted override flips a flag, always-on flags can't be
    disabled, an unknown flag is ignored, and the effective set round-trips through
    the REAL store wrappers (Get-/Set-PimFeatureFlags) -- i.e. GUI state == the
    persisted store the nav reads at boot.

.DESCRIPTION
    Three layers, all OFFLINE (no live tenant, no server boot):

      1. PURE catalog + resolver over the REAL shared lib
         (engine/_shared/PIM-FeatureFlags.ps1): defaults (core ON / advanced OFF);
         a persisted override flips a flag; the always-on guard (Settings/Home/
         Audit can't be disabled); an unknown flag id is ignored (+ warned, never
         invents a surface); JSON-string + PSCustomObject store shapes; the
         minimal-override reduction (only non-default, never always-on).

      2. GUI -> STORE -> READ round-trip through the REAL Manager wrappers
         (Get-/Set-PimFeatureFlags extracted from Open-PimManager.ps1) over an
         in-memory store stub = the SAME Get-/Set-PimManagerSetting chain the nav
         boot-injection reads pim.Settings through. Proves a saved GUI value reads
         back identically (so GUI nav state == the persisted behaviour).

      3. STATIC GUI / SERVER wiring (no dead view): the Settings tab renders the
         Features card; the nav gating reads the boot-injected flags + hides
         disabled tabs / empty groups; the server routes GET/PUT
         /api/settings/feature-flags with a SuperAdmin gate on the write and
         bakes the effective flags at boot.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root    = Split-Path -Parent $PSScriptRoot           # ...\PIM4EntraPS
$lib     = Join-Path $root 'engine\_shared\PIM-FeatureFlags.ps1'
$srvPath = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$htmlPath= Join-Path $root 'tools\pim-manager\pim-manager.html'
T 'PIM-FeatureFlags.ps1 present' (Test-Path -LiteralPath $lib)
T 'Open-PimManager.ps1 present'  (Test-Path -LiteralPath $srvPath)
T 'pim-manager.html present'     (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

Set-StrictMode -Off
. $lib

# ===========================================================================
# Layer 1 -- PURE catalog + resolver (real shared lib)
# ===========================================================================
Write-Host "`n-- Layer 1: pure catalog + resolver --" -ForegroundColor Cyan

# Catalog is well-formed: id/label/default/alwaysOn on every flag; ids unique.
$cat = Get-PimFeatureFlagCatalog
T 'catalog has entries'              (@($cat).Count -ge 15)
T 'every flag has id + label'        (@($cat | Where-Object { -not "$($_.id)".Trim() -or -not "$($_.label)".Trim() }).Count -eq 0)
T 'flag ids are unique'              ((@($cat | ForEach-Object { "$($_.id)" } | Sort-Object -Unique).Count) -eq @($cat).Count)
T 'settings is always-on'            ([bool](@($cat | Where-Object { $_.id -eq 'settings' })[0].alwaysOn))
T 'home is always-on'                ([bool](@($cat | Where-Object { $_.id -eq 'home' })[0].alwaysOn))
T 'audit is always-on'               ([bool](@($cat | Where-Object { $_.id -eq 'audit' })[0].alwaysOn))
# core ON by default, newer/advanced OFF by default (gradual rollout)
T 'map defaults ON (core)'           ([bool](@($cat | Where-Object { $_.id -eq 'map' })[0].default))
T 'approvals defaults ON (core)'     ([bool](@($cat | Where-Object { $_.id -eq 'approvals' })[0].default))
T 'accessreview defaults OFF (adv)'  (-not [bool](@($cat | Where-Object { $_.id -eq 'accessreview' })[0].default))
T 'reports defaults OFF (advanced)'  (-not [bool](@($cat | Where-Object { $_.id -eq 'reports' })[0].default))
T 'conformance defaults OFF (adv)'   (-not [bool](@($cat | Where-Object { $_.id -eq 'conformance' })[0].default))
# the catalog copy is defensive (mutating it doesn't affect the next read)
$cat[0].default = -not $cat[0].default
$cat2 = Get-PimFeatureFlagCatalog
T 'catalog returns a defensive copy' ([bool]($cat2[0].default) -ne [bool]($cat[0].default))

# DEFAULTS applied on an empty store.
$r0 = Resolve-PimFeatureFlags -Raw $null
T 'empty store -> map defaults applied' ([bool]$r0.flags['map'] -eq $true -and [bool]$r0.flags['reports'] -eq $false)
T 'empty store -> no warnings'          (@($r0.warnings).Count -eq 0)
T 'effective carries label+default+alwaysOn' ("$($r0.effective['settings'].label)".Trim() -ne '' -and [bool]$r0.effective['settings'].alwaysOn -eq $true)

# A PERSISTED OVERRIDE flips a flag (advanced ON, core OFF).
$ov = Resolve-PimFeatureFlags -Raw ([ordered]@{ flags = [ordered]@{ reports = $true; map = $false } })
T 'override turns an advanced flag ON' ([bool]$ov.flags['reports'] -eq $true)
T 'override turns a core flag OFF'     ([bool]$ov.flags['map'] -eq $false)
T 'untouched flag keeps its default'   ([bool]$ov.flags['approvals'] -eq $true)

# ALWAYS-ON flags can NEVER be disabled (no lock-out), even with an explicit override.
$lock = Resolve-PimFeatureFlags -Raw ([ordered]@{ flags = [ordered]@{ settings = $false; home = $false; audit = $false } })
T 'settings forced on despite override' ([bool]$lock.flags['settings'] -eq $true)
T 'home forced on despite override'     ([bool]$lock.flags['home'] -eq $true)
T 'audit forced on despite override'    ([bool]$lock.flags['audit'] -eq $true)
T 'always-on override is warned'        (@($lock.warnings | Where-Object { $_ -match 'always-on' }).Count -ge 1)

# An UNKNOWN flag id is IGNORED (never invents a surface) + surfaced as a warning.
$unk = Resolve-PimFeatureFlags -Raw ([ordered]@{ flags = [ordered]@{ nope = $true; alsoBogus = $false; reports = $true } })
T 'unknown flag id not added to map'    (-not $unk.flags.Contains('nope') -and -not $unk.flags.Contains('alsoBogus'))
T 'unknown flag id is warned'           (@($unk.warnings | Where-Object { $_ -match "Unknown feature flag 'nope'" }).Count -ge 1)
T 'known flag alongside unknown still applies' ([bool]$unk.flags['reports'] -eq $true)

# Accepts a FLAT id->bool map (no 'flags' wrapper) too -- a hand-edited value.
$flat = Resolve-PimFeatureFlags -Raw ([ordered]@{ reports = $true })
T 'flat (unwrapped) override map honoured' ([bool]$flat.flags['reports'] -eq $true)

# JSON-string + PSCustomObject shapes (the SQL store hands back a JSON-parsed object).
$jsonStr = ([ordered]@{ flags = [ordered]@{ reports = $true; map = $false } } | ConvertTo-Json -Depth 8)
$fromJson = Resolve-PimFeatureFlags -Raw $jsonStr
T 'JSON-string raw parsed (override read back)' ([bool]$fromJson.flags['reports'] -eq $true -and [bool]$fromJson.flags['map'] -eq $false)
$psObj = $jsonStr | ConvertFrom-Json
$fromObj = Resolve-PimFeatureFlags -Raw $psObj
T 'PSCustomObject raw read (override read back)' ([bool]$fromObj.flags['reports'] -eq $true -and [bool]$fromObj.flags['map'] -eq $false)
# Garbage JSON -> defaults + a warning (never throws / never nav-less).
$bad = Resolve-PimFeatureFlags -Raw '{not json'
T 'garbage JSON -> defaults applied'  ([bool]$bad.flags['map'] -eq $true)
T 'garbage JSON -> warned'            (@($bad.warnings | Where-Object { $_ -match 'not valid JSON' }).Count -ge 1)

# MINIMAL override reduction: only flags differing from default, never always-on.
$minOv = ConvertTo-PimFeatureFlagOverrides -Raw ([ordered]@{ flags = [ordered]@{ reports = $true; map = $true; settings = $false; approvals = $true } })
T 'reduction keeps only non-default flag' ($minOv.Contains('reports') -and [bool]$minOv['reports'] -eq $true)
T 'reduction drops a flag equal to default' (-not $minOv.Contains('map') -and -not $minOv.Contains('approvals'))
T 'reduction never stores always-on flags' (-not $minOv.Contains('settings'))

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
$getFn = Get-FnBody $srv 'Get-PimFeatureFlags'
$setFn = Get-FnBody $srv 'Set-PimFeatureFlags'
T 'Get-PimFeatureFlags body extracted' ([bool]$getFn)
T 'Set-PimFeatureFlags body extracted' ([bool]$setFn)

if ($getFn -and $setFn) {
    # In-memory store = the SAME Get-/Set-PimManagerSetting chain pim.Settings is
    # read/written through (the nav boot-injection + the GUI all read this store).
    $script:__store = @{}
    function Get-PimManagerSetting { param([Parameter(Mandatory)][string]$Name) if ($script:__store.ContainsKey($Name)) { return $script:__store[$Name] } return $null }
    function Set-PimManagerSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) $script:__store[$Name] = $Value }

    Invoke-Expression $getFn
    Invoke-Expression $setFn

    # Empty store -> fully-populated effective map (defaults, never empty).
    $g0 = Get-PimFeatureFlags
    T 'empty store reads defaults'        ([bool]$g0.flags['map'] -eq $true -and [bool]$g0.flags['reports'] -eq $false)
    T 'GET exposes the catalog'           (@($g0.catalog).Count -ge 15)

    # SAVE a GUI selection (the shape the GUI PUTs: { flags: {...} }) ...
    $saved = Set-PimFeatureFlags -Flags ([ordered]@{ flags = [ordered]@{ reports = $true; accessreview = $true; map = $false; settings = $false } })
    T 'save returns the persisted effective map' ([bool]$saved.flags['reports'] -eq $true -and [bool]$saved.flags['map'] -eq $false)
    # ... and it READS BACK IDENTICALLY through a fresh Get (proves it hit the store).
    $g1 = Get-PimFeatureFlags
    T 'override persists + reads back'    ([bool]$g1.flags['reports'] -eq $true -and [bool]$g1.flags['accessreview'] -eq $true -and [bool]$g1.flags['map'] -eq $false)
    T 'always-on stays on through store'  ([bool]$g1.flags['settings'] -eq $true)
    T 'the underlying store key is FeatureFlags' ($script:__store.ContainsKey('FeatureFlags'))
    # the store holds the MINIMAL normalized overrides (no always-on, no defaults).
    $stored = $script:__store['FeatureFlags']
    T 'stored value is minimal (no always-on key)' (-not $stored.flags.Contains('settings'))
    T 'stored value carries the real override' ([bool]$stored.flags['reports'] -eq $true)

    # SAVE an unknown flag -> store stays clean (unknown ignored, no garbage).
    [void](Set-PimFeatureFlags -Flags ([ordered]@{ flags = [ordered]@{ bogus = $true; reports = $true } }))
    $g2 = Get-PimFeatureFlags
    T 'unknown save -> not in effective map' (-not $g2.flags.Contains('bogus'))
    T 'unknown save -> known flag still applied' ([bool]$g2.flags['reports'] -eq $true)
}

# ===========================================================================
# Layer 3 -- STATIC GUI / SERVER wiring (no dead view)
# ===========================================================================
Write-Host "`n-- Layer 3: GUI + server wiring (static) --" -ForegroundColor Cyan
$html = [System.IO.File]::ReadAllText($htmlPath)
T 'server dot-sources PIM-FeatureFlags.ps1'  ($srv -match 'PIM-FeatureFlags\.ps1')
T 'server handles GET /api/settings/feature-flags' ($srv -match "\`$path -eq '/api/settings/feature-flags' -and \`$method -eq 'GET'")
T 'server handles PUT /api/settings/feature-flags' ($srv -match "\`$path -eq '/api/settings/feature-flags' -and \`$method -eq 'PUT'")
T 'PUT is SuperAdmin-gated'                   ($srv -match 'SuperAdmin role required to change feature flags')
T 'PUT writes an audit event'                ($srv -match "settings\.feature-flags\.save")
T 'server bakes flags at boot (placeholder)' ($srv -match "__PIM_FEATUREFLAGS__")
T 'boot injection runs Get-PimFeatureFlags'  ($srv -match 'Get-PimFeatureFlags')
T 'HTML carries the boot placeholder'        ($html -match '__PIM_FEATUREFLAGS__')
T 'HTML exposes PIM_FEATUREFLAGS_BOOT'        ($html -match 'window\.PIM_FEATUREFLAGS_BOOT')
T 'nav reads the effective flags'            ($html -match 'function isFeatureEnabled' -and $html -match 'applyFeatureFlagsToTabs')
T 'nav hides disabled flat tabs'             ($html -match 'applyFeatureFlagsToTabs\(\)')
T 'nav hides a group with all children off'  ($html -match 'groupItems === 0')
T 'GUI renders the Features card'            ($html -match 'renderFeaturesCard\(' -and $html -match 'id="setFeaturesBody"')
T 'GUI GETs /api/settings/feature-flags'    ($html -match "api\('GET',\s*'/api/settings/feature-flags'")
T 'GUI PUTs /api/settings/feature-flags'    ($html -match "api\('PUT',\s*'/api/settings/feature-flags'")
T 'GUI surfaces resolver warnings'          ($html -match 'p\.warnings')

# ===========================================================================
Write-Host ""
if ($fail -eq 0) { Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green; exit 0 }
else { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
