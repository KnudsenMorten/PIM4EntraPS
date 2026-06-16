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
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase   = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [int]$Port             = 8080,
    [string]$RunAsUser     = 'NT AUTHORITY\NETWORK SERVICE',   # or a gMSA / domain svc acct
    [switch]$GrantSql,                                          # also create the VM-MI DB user
    [string]$VmMiAppId,                                         # the VM system-MI appId (needed for -GrantSql)
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$mgr = Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1'
$sch = Join-Path $solRoot 'tools\pim-scheduler\Start-PimScheduler.ps1'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

# Shared setup helpers (banner + Grant-PimMiSql) + engine REST/SQL cores for the grant.
. "$here\_PimSetupShared.ps1"
. "$solRoot\engine\_shared\PIM-Rest.ps1"
. "$solRoot\engine\_shared\PIM-SqlStore.ps1"
Show-PimSetupBanner -ScriptName 'Setup-PimVM' -SolutionRoot $solRoot

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

if ($GrantSql) {
    Step "Grant the VM system-MI as a SQL contained DB user (SID-from-appId, TYPE=E)"
    if (-not ($SqlAdminClientId -and $SqlAdminClientSecret)) {
        Write-Warning "  -GrantSql needs -SqlAdminClientId + -SqlAdminClientSecret (the SQL AAD-admin SPN). Skipped."
    } elseif (-not $VmMiAppId) {
        $vmName = $env:COMPUTERNAME
        Write-Warning "  -GrantSql needs -VmMiAppId (the VM system-MI appId, shown under VM > Identity). Skipped for [$vmName]."
        Write-Warning "  Find it: az vm identity show -g <rg> -n $vmName --query principalId  ->  az ad sp show --id <principalId> --query appId"
    } else {
        $vmName = $env:COMPUTERNAME
        if ($PSCmdlet.ShouldProcess($SqlServerFqdn, "create VM-MI DB user [$vmName]")) {
            Grant-PimMiSql -DbUserName $vmName -MiAppId $VmMiAppId `
                -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId `
                -SqlAdminClientId $SqlAdminClientId -SqlAdminClientSecret $SqlAdminClientSecret
            Write-Host "  VM MI [$vmName] granted db_datareader/writer/ddladmin on $SqlDatabase." -ForegroundColor Green
        }
    }
}

Step 'Done. Manager on http://<vm-ip>:'"$Port"'/  — reachable from hub/peered clients + GSA.'
# GSA / Private Access + private-link / DNS guidance (which zones to add)
Show-PimGsaPrivateLinkGuidance
