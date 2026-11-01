<#
.SYNOPSIS
    SEC-95 (SECAUDIT-1) -- the hybrid worker's daily update source: the signed Invardia manifest, verified HERE.

.DESCRIPTION
    Run by Install-PimHybridWorker.ps1 -Phase Update (as SYSTEM) from the version that is INSTALLED on the worker
    (C:\PIM\app\current), so the keys that verify the manifest are the ones already on the machine -- never anything the
    update itself brings. It reads the install's licence and install key from pim.Settings with the machine identity, asks
    Invardia for the manifest of the worker's ring, verifies the signature, product, sequence and holds, downloads the
    archive, checks its SHA-256 and size, and re-packs it with a VERSION check (Get-PimHybridWorkerUpdateTarget ->
    Get-PimInvardiaUpdateTarget, the cloud updater's own path).

    Prints one line the installer reads:  PIM-HW-UPDATE {"ok":..,"version":..,"sequence":..,"contextPath":..,"reason":..}
    version '' = nothing moves. A failure is ok=false with the reason -- the installer then keeps the running version.

.EXAMPLE
    pwsh -File Resolve-PimHybridWorkerUpdate.ps1 -SqlServer <server>.database.windows.net -Ring 2 -StateFile C:\PIM\bin\update-state.json -RunningVersion 3.0.10
#>
param(
    [Parameter(Mandatory)][string]$SqlServer,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$Ring,
    [string]$StateFile = '',
    [string]$RunningVersion = '',
    [string]$WorkDir = ([IO.Path]::GetTempPath())
)
$ErrorActionPreference = 'Stop'
function Out-Answer([hashtable]$A) { Write-Output ('PIM-HW-UPDATE ' + ([pscustomobject]$A | ConvertTo-Json -Compress -Depth 3)) }
try {
    $shared = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'engine\_shared'
    . (Join-Path $shared 'PIM-LogOnce.ps1')
    $global:PIM_LogQuiet = $true
    . (Join-Path $shared 'PIM-Rest.ps1')
    . (Join-Path $shared 'PIM-ChangeQueue.ps1')
    . (Join-Path $shared 'PIM-SqlStore.ps1')
    . (Join-Path $shared 'PIM-LicenceRequest.ps1')
    . (Join-Path $shared 'PIM-InvardiaUpdate.ps1')
    $global:PIM_UseGraphSdk = $false
    $global:PIM_UseManagedIdentity = $true
    $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
    $cs = Get-PimSqlConnectionString
    $state = $null
    if ("$StateFile".Trim() -and (Test-Path -LiteralPath $StateFile)) { try { $state = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $state = $null } }
    $t = Get-PimHybridWorkerUpdateTarget -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n } `
            -Http { param($m, $u, $b, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } `
            -Ring $Ring -State $state -RunningVersion $RunningVersion -WorkDir $WorkDir
    Out-Answer @{ ok = [bool]$t.ok; version = "$($t.version)"; sequence = [int]$t.sequence; contextPath = "$($t.contextPath)"; hold = [bool]$t.hold
                  ahead = [bool]$t.ahead; attention = [bool]$t.attention; noKey = [bool]$t.noKey; reason = "$($t.reason)" }
} catch {
    Out-Answer @{ ok = $false; version = ''; sequence = 0; contextPath = ''; reason = "the signed update could not be resolved: $((("$($_.Exception.Message)") -split "`n")[0])" }
}
