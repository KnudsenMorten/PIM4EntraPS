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
      * Opens the firewall for the chosen port -- ONLY with -AuthLayer SignedToken (SEC-28).

    The VM MI must be a SQL contained DB user (run the grant from an AAD-admin SPN, same
    SID-from-appId pattern as the container setup — see -GrantSql).

.NOTES
    The VM is reachable from hub/peered clients + GSA directly on its IP:port — no ACA
    ingress quirks apply. For TLS, front with the existing reverse proxy / App Gateway or
    run the listener on 443 with a cert (out of scope here; internal HTTP is the default).

    🔴 SEC-28 (§33.28) -- A VM HAS NO AUTHENTICATION EDGE. This script used to deploy
    PIM_HOSTED=1 on plain HTTP with an open firewall rule and NOTHING in front: the hosted
    Manager trusts identity headers only because Easy Auth strips client-supplied copies,
    and on a VM nothing does, so anyone who could reach the port could name themselves a
    SuperAdmin. It no longer deploys an open Manager:
      -AuthLayer None (default)  the web Manager REFUSES every request (401) and the firewall
                                 rule is NOT opened. The local break-glass console
                                 (tools/pim-manager/Start-PimEmergency.ps1) still works on the box.
      -AuthLayer SignedToken     for a front end that authenticates the user and forwards a
                                 signed Entra ID token in X-MS-TOKEN-AAD-ID-TOKEN. The Manager
                                 verifies it (signature + issuer pinned to -TenantId + audience
                                 -TokenAudience) on every request. -TokenAudience is required.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase   = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [int]$Port             = 8080,
    # SEC-28: what authenticates the caller in front of the web Manager. See .NOTES.
    [ValidateSet('None', 'SignedToken')][string]$AuthLayer = 'None',
    # The audience (app registration client id) the forwarded ID token must carry -- required with SignedToken.
    [string]$TokenAudience = '',
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

# 🔴 SEC-28: decide the auth layer BEFORE touching the machine, and refuse a half-configured one.
if ($AuthLayer -eq 'SignedToken' -and -not "$TokenAudience".Trim()) {
    throw "Setup-PimVM: -AuthLayer SignedToken needs -TokenAudience (the client id the forwarded ID token is issued to). Without it the token check would accept a token minted for ANY application -- refusing."
}
$authLayerEnv = if ($AuthLayer -eq 'SignedToken') { 'signed-token' } else { 'none' }

Step "Machine env vars (PIM_HOSTED + SQL coordinates, MI via IMDS, auth layer '$authLayerEnv')"
if ($PSCmdlet.ShouldProcess('Machine env','set')) {
    [Environment]::SetEnvironmentVariable('PIM_HOSTED_AUTH_LAYER', $authLayerEnv, 'Machine')
    if ($AuthLayer -eq 'SignedToken') {
        [Environment]::SetEnvironmentVariable('PIM_HOSTED_REQUIRE_SIGNED_TOKEN', '1', 'Machine')
        [Environment]::SetEnvironmentVariable('PIM_HOSTED_EASYAUTH_AUD', "$TokenAudience".Trim(), 'Machine')
        [Environment]::SetEnvironmentVariable('PIM_HOSTED_AUTH_ISSUERS', ("https://login.microsoftonline.com/$TenantId/v2.0;https://sts.windows.net/$TenantId/"), 'Machine')
        [Environment]::SetEnvironmentVariable('PIM_HOSTED_AUTH_TENANT', $TenantId, 'Machine')
    } else {
        # Clear anything a previous run left, so a re-run to 'None' really is 'None'.
        foreach ($n in @('PIM_HOSTED_REQUIRE_SIGNED_TOKEN', 'PIM_HOSTED_EASYAUTH_AUD', 'PIM_HOSTED_AUTH_ISSUERS')) {
            [Environment]::SetEnvironmentVariable($n, $null, 'Machine')
        }
    }
    [Environment]::SetEnvironmentVariable('PIM_HOSTED','1','Machine')
    [Environment]::SetEnvironmentVariable('PIM_StorageBackend','sql','Machine')
    [Environment]::SetEnvironmentVariable('PIM_SqlServer',$SqlServerFqdn,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_SqlDatabase',$SqlDatabase,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_TenantId',$TenantId,'Machine')
    [Environment]::SetEnvironmentVariable('PIM_UseManagedIdentity','1','Machine')  # VM IMDS MI for SQL
    [Environment]::SetEnvironmentVariable('WEBSITES_PORT',"$Port",'Machine')
}

if ($AuthLayer -eq 'SignedToken') {
    Step "Firewall: allow inbound TCP $Port (hub/peered clients -- restrict it to your authenticating front end)"
    if ($PSCmdlet.ShouldProcess("TCP $Port",'open')) {
        New-NetFirewallRule -DisplayName "PIM-Manager-$Port" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -ErrorAction SilentlyContinue | Out-Null
    }
} else {
    Step "Firewall: NOT opening TCP $Port -- no authentication layer is in front of the web Manager"
    Write-Warning ("  The web Manager on this VM refuses every request (401) until a front end that forwards a signed Entra ID " +
                   "token is in place: re-run with -AuthLayer SignedToken -TokenAudience <client id>. " +
                   "The local break-glass console (tools\pim-manager\Start-PimEmergency.ps1) works on this box meanwhile.")
    if ($PSCmdlet.ShouldProcess("PIM-Manager-$Port", 'remove an inbound rule a previous run opened')) {
        Remove-NetFirewallRule -DisplayName "PIM-Manager-$Port" -ErrorAction SilentlyContinue
    }
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

if ($AuthLayer -eq 'SignedToken') {
    Step 'Done. Manager on http://<vm-ip>:'"$Port"'/ -- reach it ONLY through the authenticating front end (signed ID token required).'
} else {
    Step 'Done. Scheduler running. The web Manager is deployed CLOSED (no auth layer): every request is refused until -AuthLayer SignedToken.'
}
# GSA / Private Access + private-link / DNS guidance (which zones to add)
Show-PimGsaPrivateLinkGuidance
