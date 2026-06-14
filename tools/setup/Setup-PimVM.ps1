#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS — native VM host (alternative to the container deployment).

.DESCRIPTION
    Runs the Manager (web) and the scheduler/job runner natively on a Windows VM that
    sits in the connectivity hub VNet (e.g. alongside MGMT/DC). Use this when you want
    a single always-on box instead of Container Apps. The VM's **system-assigned
    managed identity** authenticates to SQL (MI-only) via IMDS — rock-solid on a VM,
    no secret, no SQL user.

    What it sets up on THIS VM:
      * Two Scheduled Tasks running at startup as the configured service account:
          - PIM-Manager   :  Open-PimManager.ps1 -Hosted -NoLaunch   (HttpListener :8080)
          - PIM-Scheduler :  Start-PimScheduler.ps1                   (job runner)
        (HttpListener binds fine on a VM — admin/URL-ACL available, unlike App Service.)
      * Sets the machine env vars the apps read (PIM_HOSTED, SQL coordinates).
      * Opens the firewall for the chosen port.

    The VM MI must be a SQL contained DB user (run the grant from an AAD-admin SPN, same
    SID-from-appId pattern as the container setup — see -GrantSql).

.NOTES
    The VM is reachable from hub/peered clients + GSA directly on its IP:port — no ACA
    ingress quirks apply. For TLS, front with the existing reverse proxy / App Gateway or
    run the listener on 443 with a cert (out of scope here; internal HTTP is the default).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SqlServerFqdn = 'sql-pimplatform-we484.database.windows.net',
    [string]$SqlDatabase   = 'PimPlatform',
    [string]$TenantId      = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e',
    [int]$Port             = 8080,
    [string]$RunAsUser     = 'NT AUTHORITY\NETWORK SERVICE',   # or a gMSA / domain svc acct
    [switch]$GrantSql,                                          # also create the VM-MI DB user
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$mgr = Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1'
$sch = Join-Path $solRoot 'tools\pim-scheduler\Start-PimScheduler.ps1'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

Step "Machine env vars (PIM_HOSTED + SQL coordinates, MI via IMDS)"
if ($PSCmdlet.ShouldProcess('Machine env','set')) {
    [Environment]::SetEnvironmentVariable('PIM_HOSTED','1','Machine')
    [Environment]::SetEnvironmentVariable('PIM_StorageBackend','sql','Machine')
    [Environment]::SetEnvironmentVariable('PIM_SqlServer',$SqlServerFqdn,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_SqlDatabase',$SqlDatabase,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_TenantId',$TenantId,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_UseManagedIdentity','1','Machine')  # VM IMDS MI for SQL
    [Environment]::SetEnvironmentVariable('WEBSITES_PORT',"$Port",'Machine')
}

Step "Firewall: allow inbound TCP $Port (hub/peered clients)"
if ($PSCmdlet.ShouldProcess("TCP $Port",'open')) {
    New-NetFirewallRule -DisplayName "PIM-Manager-$Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -ErrorAction SilentlyContinue | Out-Null
}

Step "Scheduled Task: PIM-Manager (Open-PimManager.ps1 -Hosted)"
if ($PSCmdlet.ShouldProcess('PIM-Manager','register')) {
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$mgr`" -Hosted -NoLaunch"
    $t = New-ScheduledTaskTrigger -AtStartup
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'PIM-Manager' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Start-ScheduledTask -TaskName 'PIM-Manager'
}

Step "Scheduled Task: PIM-Scheduler (Start-PimScheduler.ps1)"
if ($PSCmdlet.ShouldProcess('PIM-Scheduler','register')) {
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$sch`""
    $t = New-ScheduledTaskTrigger -AtStartup
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'PIM-Scheduler' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Start-ScheduledTask -TaskName 'PIM-Scheduler'
}

if ($GrantSql -and $SqlAdminClientId -and $SqlAdminClientSecret) {
    Step "Grant the VM system-MI as a SQL contained DB user"
    if ($PSCmdlet.ShouldProcess($SqlServerFqdn,'create VM-MI DB user')) {
        $vmName = $env:COMPUTERNAME
        $vmMiAppId = (Invoke-RestMethod -Headers @{Metadata='true'} -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -TimeoutSec 5).resourceId  # for display
        Write-Host "  Run the same SID-from-appId grant as Setup-PimContainers.ps1 for the VM MI ($vmName)." -ForegroundColor Yellow
        Write-Host "  (The VM MI appId is shown in the portal under the VM > Identity; create [<vmname>] WITH SID=<appId bytes>, TYPE=E.)" -ForegroundColor Yellow
    }
}

Step 'Done. Manager on http://<vm-ip>:'"$Port"'/  — reachable from hub/peered clients + GSA.'
