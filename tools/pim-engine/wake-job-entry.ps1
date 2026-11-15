#Requires -Version 5.1
<#
.SYNOPSIS
    WAKE-1 (framework SECURE-WEB-1 point 1, 3.1.26) -- the in-container entry point of the wake job (caj-pim-wake).

.DESCRIPTION
    The platform starts this job when a message arrives on the wake queue 'pim-wake' (Container Apps event trigger, KEDA
    azure-queue scaler as the engine's user-assigned identity). The Manager puts that message there after a Commit / "Run
    now"; it holds 'Storage Queue Data Message Sender' on that one queue and no job right.

    THIS JOB IS THE GATE (engine/_shared/PIM-Wake.ps1 Invoke-PimWakeJob / Test-PimWakeMessage): it takes the waiting
    messages (deleted at once), refuses one older than 15 minutes, one without a readable insertion time, one carrying
    anything but a job NAME, and a name that is not on its shipped allow-list; every accepted / refused message is audited
    (pim.AuditEvents wake.accepted / wake.refused). When one is accepted it runs that name ONCE -- 'engine' = one normal
    engine run (tools/pim-scheduler/Start-PimScheduler.ps1 -Once, the same claims, leases, guards and run records as a
    scheduled start), in a child process. Nothing from the message reaches the command line or the environment.

.NOTES
    Inputs (environment written by tools/setup/Deploy-PimWakeJob.ps1 / the updater's wake step, copied from the engine job):
    PIM_WAKE_STORAGE (the storage account), PIM_ManagedIdentityClientId (the engine identity), the store settings.
    ASCII only.
#>
[CmdletBinding()]
param([string]$StorageAccount = "$($env:PIM_WAKE_STORAGE)")
$ErrorActionPreference = 'Stop'
function JobLog { param([string]$m, [string]$lvl = 'INFO') Write-Host ("[{0}] [wake-job] [{1}] {2}" -f ([datetime]::UtcNow.ToString('o')), $lvl, $m) }

$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
$sched   = Join-Path $solRoot 'tools\pim-scheduler\Start-PimScheduler.ps1'
JobLog '==== PIM Manager wake job starting ===='
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-Wake.ps1'))) { JobLog "engine shared folder not found at '$shared'" 'ERROR'; exit 3 }
. (Join-Path $shared 'PIM-Wake.ps1')
if (-not (Test-PimWakeStorageAccountName $StorageAccount)) { JobLog "REFUSED: PIM_WAKE_STORAGE '$StorageAccount' is not a storage account name" 'ERROR'; exit 2 }
if (-not "$($env:IDENTITY_ENDPOINT)".Trim()) { JobLog 'REFUSED: no managed identity endpoint -- this entry runs inside a Container Apps job with its managed identity' 'ERROR'; exit 2 }
$miCid = "$($env:PIM_ManagedIdentityClientId)".Trim()
if ($miCid) { $global:PIM_ManagedIdentityClientId = $miCid }
$global:PIM_UseGraphSdk = $false
$global:PIM_UseManagedIdentity = $true
if ("$($env:PIM_SqlServer)".Trim()) { $global:PIM_SqlServer = "$($env:PIM_SqlServer)".Trim() }
if ("$($env:PIM_SqlDatabase)".Trim()) { $global:PIM_SqlDatabase = "$($env:PIM_SqlDatabase)".Trim() }

. (Join-Path $shared 'PIM-Rest.ps1')
# the audit trail (pim.AuditEvents) -- best effort: a missing store is said by Write-PimAuditEvent, it never blocks the gate
try { . (Join-Path $shared 'PIM-SqlStore.ps1'); . (Join-Path $shared 'PIM-AuditEvent.ps1') } catch { JobLog "the audit writer did not load: $($_.Exception.Message)" 'WARN' }

$http = {
    param($m, $u, $h, $b)
    try {
        $r = if ($null -ne $b) { Invoke-WebRequest -UseBasicParsing -Method $m -Uri $u -Headers $h -Body $b -ContentType 'application/xml' -TimeoutSec 30 }
             else { Invoke-WebRequest -UseBasicParsing -Method $m -Uri $u -Headers $h -TimeoutSec 30 }
        return @{ Status = [int]$r.StatusCode; Body = "$($r.Content)" }
    } catch {
        $sc = 0; try { $sc = [int]$_.Exception.Response.StatusCode } catch { $sc = 0 }
        if ($sc) { return @{ Status = $sc; Body = '' } }
        throw
    }
}
$audit = {
    param($action, $result, $after)
    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
        Write-PimAuditEvent -Action $action -Target "queue:$(Get-PimWakeQueueName)" -After $after -Result $result -Actor "engine:$(Get-PimWakeJobName)"
    } else { JobLog "AUDIT NOT RECORDED ($action): no audit writer" 'WARN' }
}
$run = {
    param($kind)
    # the allow-list decides what each name runs -- never the message
    switch -CaseSensitive ($kind) {
        'engine' {
            $pw = (Get-Process -Id $PID).Path
            & $pw -NoProfile -File $sched -Once
            return [int]$LASTEXITCODE
        }
        default { JobLog "no runner for '$kind'" 'ERROR'; return 2 }
    }
}
$res = Invoke-PimWakeJob -StorageAccount $StorageAccount -Http $http -Run $run -Audit $audit -Say { param($m) JobLog $m }
JobLog "==== wake job done: $($res.accepted) accepted, $($res.refused) refused, ran: $($res.ran), exit $($res.exitCode) ===="
exit ([int]$res.exitCode)
