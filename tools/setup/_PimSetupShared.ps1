#requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for the PIM4EntraPS setup/deploy family (container / VM / MSP /
    engine app-registration).

.DESCRIPTION
    Dot-source this from any Setup-Pim*.ps1 / Install-Pim*.ps1 script. It provides:

      * Show-PimSetupBanner       -- SI-parity deploy banner (PowerShell + .NET +
                                     az CLI + Graph SDK versions printed up front).
      * Get-PimSetupSolutionVersion -- the VERSION file value.
      * Assert-PimSetupRegion     -- region guard: West Europe / Denmark East only;
                                     France is explicitly refused (data-residency).
      * Grant-PimMiSql            -- create/refresh a contained SQL DB user for a
                                     managed-identity/app appId (SID-from-appId,
                                     TYPE=E). MI-only, no SQL login.
      * Grant-PimMiGraph          -- assign the directory app-roles the engine needs
                                     to an MI/SPN object (idempotent).
      * Set-PimSqlNoAutoPause     -- assert/disable Azure SQL serverless auto-pause
                                     (persistent compute, REQUIREMENTS S5).
      * Get-PimGsaPrivateLinkGuidance / Show-PimGsaPrivateLinkGuidance --
                                     the GSA / Private Access + private-link/DNS
                                     advice (which zones to add) printed at the end
                                     of a deploy.
      * Write-PimDnsRecord        -- register the Manager FQDN -> env static IP on an
                                     AD DNS server (extracted from Setup-PimContainers).

    Everything is REST / az-CLI based and PS 5.1-safe (no ?./??, no
    RSA.ImportFromPem, no PS7-only members). No real tenant/subscription/customer
    values are baked in -- callers pass them.
#>

# Region allow-list. West Europe + Denmark East only. France is REFUSED.
$script:PimAllowedRegions = @('westeurope','denmarkeast')
$script:PimDeniedRegions  = @('francecentral','francesouth')

function Get-PimSetupSolutionVersion {
    [CmdletBinding()] param([string]$SolutionRoot)
    if (-not $SolutionRoot) {
        $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $SolutionRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\PIM4EntraPS
    }
    $vf = Join-Path $SolutionRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) { return ((Get-Content -LiteralPath $vf -Raw).Trim()) }
    return 'unknown'
}

function Show-PimSetupBanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string]$SolutionRoot,
        [string[]]$GraphModules,
        [string[]]$AzModules
    )
    $ver = Get-PimSetupSolutionVersion -SolutionRoot $SolutionRoot
    Write-Host ''
    Write-Host "==========================================================================" -ForegroundColor Cyan
    Write-Host " $ScriptName -- PIM4EntraPS $ver" -ForegroundColor Cyan
    Write-Host "==========================================================================" -ForegroundColor Cyan
    Write-Host ("  PowerShell : {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) -ForegroundColor Cyan
    $dotnet = try { [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription } catch { [System.Environment]::Version.ToString() }
    Write-Host ("  .NET       : {0}" -f $dotnet) -ForegroundColor Cyan
    $azv = $null
    try {
        $azJson = az version -o json 2>$null | ConvertFrom-Json
        if ($azJson) { $azv = $azJson.'azure-cli' }
    } catch {}
    Write-Host ("  az CLI     : {0}" -f $(if ($azv) { "v$azv" } else { 'not found (install Azure CLI)' })) -ForegroundColor Cyan
    foreach ($m in @($GraphModules | Where-Object { $_ })) {
        $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host ("  {0,-10}: {1}" -f $m, $(if ($mod) { "v$($mod.Version)" } else { 'not installed' })) -ForegroundColor Cyan
    }
    foreach ($m in @($AzModules | Where-Object { $_ })) {
        $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
        Write-Host ("  {0,-10}: {1}" -f $m, $(if ($mod) { "v$($mod.Version)" } else { 'not installed' })) -ForegroundColor Cyan
    }
    Write-Host ''
}

function Assert-PimSetupRegion {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Location)
    $norm = ($Location -replace '\s','').ToLowerInvariant()
    if ($norm -in $script:PimDeniedRegions) {
        throw "Region '$Location' is not allowed for PIM hosting (data residency). Use West Europe ('westeurope') or Denmark East ('denmarkeast') -- never France."
    }
    if ($norm -notin $script:PimAllowedRegions) {
        throw "Region '$Location' is not an approved PIM hosting region. Approved: $($script:PimAllowedRegions -join ', '). (France is explicitly disallowed.)"
    }
    return $norm
}

function ConvertTo-PimSqlSidFromAppId {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$AppId)
    $g = [guid]$AppId
    return '0x' + (($g.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Grant-PimMiSql {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DbUserName,
        [Parameter(Mandatory)][string]$MiAppId,
        [Parameter(Mandatory)][string]$SqlServerFqdn,
        [Parameter(Mandatory)][string]$SqlDatabase,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SqlAdminClientId,
        [Parameter(Mandatory)][string]$SqlAdminClientSecret
    )
    $global:PIM_TenantId = $TenantId
    $global:PIM_ClientId = $SqlAdminClientId
    $global:PIM_ClientSecret = $SqlAdminClientSecret
    $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $SqlAdminClientId -ClientSecret $SqlAdminClientSecret -Force
    $sid = ConvertTo-PimSqlSidFromAppId -AppId $MiAppId
    $cs  = "Server=tcp:$SqlServerFqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $c = New-PimSqlConnection -ConnectionString $cs
    $c.Open()
    try {
        $b = @"
IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$DbUserName') DROP USER [$DbUserName];
CREATE USER [$DbUserName] WITH SID = $sid, TYPE = E;
ALTER ROLE db_datareader ADD MEMBER [$DbUserName];
ALTER ROLE db_datawriter ADD MEMBER [$DbUserName];
ALTER ROLE db_ddladmin   ADD MEMBER [$DbUserName];
"@
        $cmd = $c.CreateCommand(); $cmd.CommandText = $b; [void]$cmd.ExecuteNonQuery()
    } finally { $c.Close() }
}

$script:PimGraphAppRoles = @{
    'Directory.Read.All'                       = '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
    'User.ReadWrite.All'                       = '741f803b-c850-494e-b5df-cde7c675a1ca'
    'Group.ReadWrite.All'                      = '62a82d76-70ea-41e2-9197-370581804d09'
    'RoleManagement.ReadWrite.Directory'       = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
    'PrivilegedAccess.ReadWrite.AzureADGroup'  = '618b6020-bca8-4de6-99f6-ef445fa4d857'
    'RoleManagementPolicy.ReadWrite.Directory' = 'a2611786-80b3-417e-adaa-707d4261a5f0'
    'AdministrativeUnit.ReadWrite.All'         = '5eb59dd3-1da2-4329-8733-9dabdc435916'
    'UserAuthenticationMethod.ReadWrite.All'   = '50483e42-d915-4231-9639-7fdb7fd190e5'
}

function Get-PimGraphAppRoleMap {
    [CmdletBinding()] param()
    $h = @{}; foreach ($k in $script:PimGraphAppRoles.Keys) { $h[$k] = $script:PimGraphAppRoles[$k] }
    return $h
}

function Grant-PimMiGraph {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$MiObjectId)
    $gtok = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
    if (-not $gtok) { throw "Grant-PimMiGraph: no Graph token (run 'az login' as a role-assigner)." }
    $gh = @{ Authorization = "Bearer $gtok"; 'Content-Type' = 'application/json' }
    $graphSp = (Invoke-RestMethod -Headers $gh -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'").value[0]
    foreach ($r in $script:PimGraphAppRoles.GetEnumerator()) {
        try {
            Invoke-RestMethod -Method POST -Headers $gh -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MiObjectId/appRoleAssignments" `
                -Body (@{ principalId = $MiObjectId; resourceId = $graphSp.id; appRoleId = $r.Value } | ConvertTo-Json) -ErrorAction Stop | Out-Null
        } catch {
            if ("$($_.Exception.Message)" -notmatch 'already') { Write-Warning "  graph role $($r.Key): $($_.Exception.Message)" }
        }
    }
}

function Set-PimSqlNoAutoPause {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SqlServerName,
        [Parameter(Mandatory)][string]$SqlDatabase
    )
    $delay = az sql db show -g $ResourceGroup -s $SqlServerName -n $SqlDatabase --query autoPauseDelay -o tsv 2>$null
    if (-not $delay) { Write-Warning "  could not read autoPauseDelay for $SqlServerName/$SqlDatabase (skip; may be provisioned compute)."; return }
    if ([string]$delay -eq '-1') { Write-Host "  SQL persistent compute already enforced (autoPauseDelay = -1)." -ForegroundColor DarkGray; return }
    if ($PSCmdlet.ShouldProcess("$SqlServerName/$SqlDatabase", 'disable serverless auto-pause (set autoPauseDelay -1)')) {
        az sql db update -g $ResourceGroup -s $SqlServerName -n $SqlDatabase --auto-pause-delay -1 -o none 2>$null
        Write-Host "  SQL auto-pause disabled (autoPauseDelay -1) -- persistent compute enforced." -ForegroundColor Green
    }
}

function Write-PimDnsRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$DnsServer,
        [Parameter(Mandatory)][string]$Fqdn,
        [Parameter(Mandatory)][string]$EnvDomain,
        [Parameter(Mandatory)][string]$StaticIp
    )
    if (-not (Get-Command Add-DnsServerResourceRecordA -ErrorAction SilentlyContinue)) {
        Write-Warning "  DnsServer module not available -- skip AD DNS registration for $Fqdn (add manually: A '$Fqdn' -> $StaticIp)."
        return
    }
    if (-not $PSCmdlet.ShouldProcess($DnsServer, "A $Fqdn -> $StaticIp")) { return }
    $zone = $EnvDomain
    $name = $Fqdn.Substring(0, $Fqdn.Length - $zone.Length - 1)
    if (-not (Get-DnsServerZone -ComputerName $DnsServer -Name $zone -ErrorAction SilentlyContinue)) {
        Add-DnsServerPrimaryZone -ComputerName $DnsServer -Name $zone -ReplicationScope Forest
    }
    foreach ($n in @('*', $name)) {
        $old = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $n -RRType A -ErrorAction SilentlyContinue
        if ($old) { Remove-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $zone -Name $n -RRType A -Force -ErrorAction SilentlyContinue }
        Add-DnsServerResourceRecordA -ComputerName $DnsServer -ZoneName $zone -Name $n -IPv4Address $StaticIp -ErrorAction SilentlyContinue
    }
}

function Get-PimGsaPrivateLinkGuidance {
    [CmdletBinding()] param([string]$ManagerFqdn)
    $mgr = if ($ManagerFqdn) { $ManagerFqdn } else { '<manager-fqdn>' }
    @"
GSA / Private Access + private-link / DNS checklist
---------------------------------------------------
Goal: cloud-only users reach the INTERNAL Manager (no public IP) without a VPN,
and on-prem/peered clients resolve the private names. The Manager stays private
(internal ACA env with --ingress external = a static private IP, no public exposure).

1. Entra Global Secure Access -- Private Access (not suffix-based):
   * Define the Manager as a Private Access application targeting its private FQDN/IP:
       host = $mgr   (or the ACA env static IP)   port = 443 (or 80 internal HTTP)
   * Assign the access policy to the cloud-only user/group that must reach it.
   * Install/enable the GSA client on those endpoints; it tunnels to the private app
     over the Microsoft backbone -- no VPN, no public ingress.
   * Verify the connector/forwarding profile covers the Manager FQDN and the SQL/KV
     private names below.

2. Private-link DNS zones to add (link each to the spoke VNet, and forward from any
   custom/on-prem DNS so the VNet resolves them):
   * privatelink.database.windows.net   -- Azure SQL  (PRESENT in this env; keep it)
   * privatelink.azurewebsites.net      -- ADD if the Manager runs on App Service
                                           (App Service private endpoint web-app zone)
   * privatelink.blob.core.windows.net  -- run-staging storage / MSP signed-baseline pulls
   * privatelink.vaultcore.azure.net    -- Key Vault (app-only cert/secret over PE)
   NOTE: an ACA *internal* environment with --ingress external publishes the env's
   default domain to a STATIC private IP -- register that name on AD DNS (this script
   does that via -DnsServer); it does not need a privatelink.* zone of its own.

3. Custom-DNS VNets (on-prem domain controllers as the VNet DNS):
   custom-DNS VNets do NOT resolve Azure privatelink.* zones automatically. Production
   fix = a conditional forwarder (or Azure DNS Private Resolver) on the DCs sending
   database.windows.net / azurewebsites.net / blob.core.windows.net / vaultcore.azure.net
   to 168.63.129.16. Hosts-file entries are a bootstrap stopgap ONLY.
"@
}

function Show-PimGsaPrivateLinkGuidance {
    [CmdletBinding()] param([string]$ManagerFqdn)
    Write-Host (Get-PimGsaPrivateLinkGuidance -ManagerFqdn $ManagerFqdn) -ForegroundColor Yellow
}
