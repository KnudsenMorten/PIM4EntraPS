#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-19 -- the engine's directory snapshot must be REFRESHED at the start of every
    run, not built once and kept for the life of the process.

    What happened: the only path that ever built the context was
    Ensure-PimContextLoaded, whose entire body is

        if (-not $Global:PimContextBuiltAt) { Build-PimContext }

    -- no -Refresh, no age check -- and Invoke-PimEngineCore never called
    Build-PimContext at all. So the first build in a process was the last one, and
    Build-PimContext's own -Refresh / $CacheSeconds parameters were unreachable from
    the engine. The scheduler is a `while ($true) { tick; Start-Sleep }` loop that
    calls Invoke-PimEngine IN-PROCESS, so a deployed container reconciled against the
    directory as it looked when the container STARTED, for as long as it ran.

    Observed live 2026-08-06: after two AUs were deleted out of band, five consecutive
    passes reported `AdministrativeUnits live=18 create=0 nochange=2` for AUs that no
    longer existed, and every dependent member write 404'd on the dead ids. The Groups
    count moved 79 -> 85 across the same passes because that provider does its own live
    read -- which is what ruled out Entra replication and pointed at the snapshot.

    Why it is not cosmetic: the engine reported `nochange` -- the one word an operator
    reads as "reconciled" -- for objects that were GONE. A stale snapshot that reports
    success is worse than a failure that reports itself.

    The assertions that keep it fixed: an engine run whose snapshot is older than the
    freshness bound RE-FETCHES and therefore SEES an out-of-band deletion; runs inside
    the bound do not re-fetch (so a per-scope fan-out does not hammer Graph); and the
    old buggy shape -- "built once, never again" -- is asserted DEAD.

    Offline. No tenant, no network: Invoke-PimGraph is stubbed and the fetch count is
    what is measured.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-ContextBuilder.ps1')
. (Join-Path $shared 'PIM-EngineCore.ps1')
. (Join-Path $shared 'PIM-EngineProviders.ps1')

Write-Host "=== BUG-19: the directory context is refreshed at the start of every engine run ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Test double: Build-PimContext's REAL body runs (that is the point -- the cache
# decision under test is its own), but the Graph fetch is stubbed. $script:AuSet is
# what "the directory" currently holds, so deleting an AU is just changing it.
# ---------------------------------------------------------------------------
$script:Fetches = 0
$script:AuSet   = @(
    [pscustomobject]@{ id = 'au-1'; displayName = 'PIM-TEST-AU-One' }
    [pscustomobject]@{ id = 'au-2'; displayName = 'PIM-TEST-AU-Two' }
)
function Invoke-PimGraph {
    param([string]$Method = 'GET', [string]$Path, [object]$Body, [switch]$All, [switch]$Beta, [hashtable]$Headers = @{})
    if ("$Path" -match 'administrativeUnits') { $script:Fetches++; return $script:AuSet }
    if ("$Path" -match 'roleDefinitions')     { return @() }
    if ("$Path" -match '/groups')             { return @() }
    if ("$Path" -match '/users')              { return @() }
    return @()
}
function ConvertTo-PimSdkShape { param([Parameter(ValueFromPipeline)][object]$InputObject) process { $InputObject } }
$global:PIM_Filters   = @{}          # no filters -> the filter loop is skipped, fetch still happens
$global:PIM_UseGraphSdk = $false
$global:PIM_LeanContext = $true

function Reset-ContextState {
    $Global:PimContextBuiltAt = $null
    $Global:AU_All_ID = @()
    $script:Fetches = 0
}

# ---------------------------------------------------------------------------
# 1. The freshness bound itself
# ---------------------------------------------------------------------------
Write-Host "`n-- the per-run freshness bound --" -ForegroundColor Yellow
$global:PIM_ContextMaxAgeSeconds = $null
Assert "default max age is 30s"                      ((Get-PimContextMaxAgeSeconds) -eq 30)
$global:PIM_ContextMaxAgeSeconds = 120
Assert "an operator override is honoured"            ((Get-PimContextMaxAgeSeconds) -eq 120)
$global:PIM_ContextMaxAgeSeconds = 'not-a-number'
Assert "garbage falls back to the default"           ((Get-PimContextMaxAgeSeconds) -eq 30)
$global:PIM_ContextMaxAgeSeconds = -5
Assert "a negative age clamps to 0 (always fresh)"   ((Get-PimContextMaxAgeSeconds) -eq 0)
$global:PIM_ContextMaxAgeSeconds = $null

# ---------------------------------------------------------------------------
# 2. THE REGRESSION: a stale snapshot must be re-fetched, and the re-fetch must
#    actually change what the engine believes. This is the live failure in miniature.
# ---------------------------------------------------------------------------
Write-Host "`n-- an out-of-band deletion is SEEN by the next run --" -ForegroundColor Yellow
Reset-ContextState
[void](Update-PimEngineRunContext)
Assert "run 1 fetches the directory"                 ($script:Fetches -eq 1)
Assert "run 1 sees both AUs"                         (@($Global:AU_All_ID).Count -eq 2)

# ...someone deletes an AU in the portal, and the snapshot is now older than the bound.
$script:AuSet = @([pscustomobject]@{ id = 'au-1'; displayName = 'PIM-TEST-AU-One' })
$Global:PimContextBuiltAt = (Get-Date).AddMinutes(-10)
[void](Update-PimEngineRunContext)
Assert "run 2 re-fetches once the snapshot is stale" ($script:Fetches -eq 2)
Assert "run 2 SEES the deletion (2 -> 1 AU)"         (@($Global:AU_All_ID).Count -eq 1)
Assert "the deleted AU is gone from the snapshot"    (-not (@($Global:AU_All_ID) | Where-Object { "$($_.id)" -eq 'au-2' }))

# ---------------------------------------------------------------------------
# 3. The old buggy shape is DEAD. Before the fix, Ensure-PimContextLoaded's
#    "if (-not $Global:PimContextBuiltAt)" meant a built context could NEVER be
#    rebuilt. Assert the engine run boundary does not behave that way.
# ---------------------------------------------------------------------------
Write-Host "`n-- 'built once, never again' is gone --" -ForegroundColor Yellow
Reset-ContextState
[void](Update-PimEngineRunContext)
$before = $script:Fetches
$Global:PimContextBuiltAt = (Get-Date).AddHours(-8)     # a long-lived scheduler container
[void](Update-PimEngineRunContext)
Assert "an 8-hour-old snapshot is NOT reused"        ($script:Fetches -eq ($before + 1))

# ---------------------------------------------------------------------------
# 4. ...but a fan-out of scopes inside one tick must not re-fetch per scope.
# ---------------------------------------------------------------------------
Write-Host "`n-- a per-scope fan-out does not hammer Graph --" -ForegroundColor Yellow
Reset-ContextState
[void](Update-PimEngineRunContext)
for ($i = 0; $i -lt 19; $i++) { [void](Update-PimEngineRunContext) }
Assert "19 further runs inside the bound = 1 fetch"  ($script:Fetches -eq 1)

# ---------------------------------------------------------------------------
# 5. A failing refresh must not kill the run -- and must not be silent.
# ---------------------------------------------------------------------------
Write-Host "`n-- a broken refresh degrades, loudly --" -ForegroundColor Yellow
Reset-ContextState
function Build-PimContext { param([switch]$Refresh, [int]$CacheSeconds = 300) throw 'graph is down' }
$warn = @()
$ok = Update-PimEngineRunContext -WarningVariable warn -WarningAction SilentlyContinue
Assert "a failed refresh returns false, not an exception" ($ok -eq $false)
Assert "and it WARNS (silence is how BUG-19 hid)"         (@($warn).Count -ge 1)

# ---------------------------------------------------------------------------
# 6. Source guard: the engine entry must actually call the refresh. A future edit
#    that drops the call would leave every behavioural test above still passing.
# ---------------------------------------------------------------------------
Write-Host "`n-- the engine entry point still calls it --" -ForegroundColor Yellow
$core = Get-Content (Join-Path $shared 'PIM-EngineCore.ps1') -Raw
$fn   = [regex]::Match($core, 'function Invoke-PimEngine\b.*?\n\}', 'Singleline').Value
Assert "Invoke-PimEngine calls Update-PimEngineRunContext" ($fn -match 'Update-PimEngineRunContext')

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
