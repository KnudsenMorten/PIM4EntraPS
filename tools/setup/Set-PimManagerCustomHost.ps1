<#
.SYNOPSIS
  §80.1 -- give the PIM Manager a custom DNS name, e.g. pim-manager.<internal dns domain>, next to its generated
  Container Apps address.

.DESCRIPTION
  Operator 2026-09-29: "We need option to add custom dns name to the url, like pim-manager.<internal dns domain>."

  What it does, in order (every step idempotent; -WhatIf shows the plan and changes nothing):
    1. reads the Manager app and its Container Apps environment (internal-only or external, static IP, default domain);
    2. adds the host name to the app;
    3. binds a certificate:
         - INTERNAL environment: YOUR certificate for that name -- from Key Vault (-KeyVaultName/-KeyVaultCertName) or a
           PFX file (-PfxPath). A free managed certificate cannot be validated on a private environment.
         - EXTERNAL environment: a free managed certificate (CNAME validation) once the public records exist;
    4. DNS:
         - INTERNAL: an A record <label> -> environment static IP in a Private DNS zone named after the rest of the host
           name (pim-manager.corp.local -> zone corp.local, record pim-manager), linked to -LinkVnetIds; or on an AD DNS
           server (-Dns AdDns -AdDnsServer dc1);
         - EXTERNAL: prints the CNAME + TXT (asuid) records for your public DNS;
    5. adds the name to PIM_MANAGER_HOSTNAMES on the app (mail links then use it -- Resolve-PimManagerMailUrl);
    6. adds https://<name>/.auth/login/aad/callback to the Manager's Easy Auth app registration (Graph).

  Graph step: needs an az profile signed in to the ENVIRONMENT's tenant (AZURE_CONFIG_DIR); the script refuses when the
  active tenant differs from -TenantId (memory: Graph follows the default az profile, which on mgmt1 is another company).

.EXAMPLE
  # internal environment, certificate in Key Vault, private DNS zone in the hub RG, linked to the hub + PIM VNets
  $env:AZURE_CONFIG_DIR = '<an az profile signed in to this tenant>'
  .\Set-PimManagerCustomHost.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup <pim-rg> `
      -HostName pim-manager.corp.local -KeyVaultName kv-x -KeyVaultCertName pim-manager-corp-local `
      -PrivateDnsResourceGroup <dns-rg> -LinkVnetIds <hubVnetId>,<pimVnetId> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$HostName,
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$KeyVaultName,
    [string]$KeyVaultCertName,
    [string]$PfxPath,
    [securestring]$PfxPassword,
    [ValidateSet('Auto', 'PrivateDnsZone', 'AdDns', 'None')][string]$Dns = 'Auto',
    [string]$PrivateDnsResourceGroup,
    [string[]]$LinkVnetIds = @(),
    [string]$AdDnsServer,
    [switch]$PublicDnsReady,
    [switch]$SkipEasyAuth
)
$ErrorActionPreference = 'Stop'

function Get-PimManagerCustomHostPlan {
    <#
      PURE. Decides every step from the facts; refuses what cannot work. Returns @{ ok; reason; host; zone; label;
      internal; certificate (managed|keyvault|pfx); dns (privatezone|addns|public|none); steps[]; records[] }.
    #>
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][bool]$Internal,
        [string]$EnvDefaultDomain = '',
        [string]$EnvStaticIp = '',
        [string]$KeyVaultName = '', [string]$KeyVaultCertName = '', [string]$PfxPath = '',
        [ValidateSet('Auto', 'PrivateDnsZone', 'AdDns', 'None')][string]$Dns = 'Auto',
        [string]$AdDnsServer = '',
        [string]$AppFqdn = '', [string]$VerificationId = ''
    )
    $h = "$HostName".Trim().ToLowerInvariant().TrimEnd('.')
    $refuse = { param($why) @{ ok = $false; reason = $why; host = $h } }
    if ($h -notmatch '^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$') { return (& $refuse "'$HostName' is not a valid DNS host name") }
    $parts = $h.Split('.')
    if ($parts.Count -lt 3) { return (& $refuse "'$h' needs at least three labels (name.domain.tld), e.g. pim-manager.corp.local") }
    if ($EnvDefaultDomain -and ($h -eq $EnvDefaultDomain.ToLowerInvariant() -or $h.EndsWith('.' + $EnvDefaultDomain.ToLowerInvariant()))) {
        return (& $refuse "'$h' is inside the environment's own default domain -- that name exists already; pick a name in YOUR domain")
    }
    $label = $parts[0]; $zone = ($parts[1..($parts.Count - 1)] -join '.')
    # Operator decision 2026-09-29: custom names are OPTIONAL. An EXTERNAL environment keeps its default name or takes a
    # PUBLIC subdomain -- Azure validates the name through public DNS (TXT asuid + CNAME), which a private TLD never passes.
    # A private name belongs to a VNet-INTERNAL environment (a customer build on a private network), with a CNAME / private record.
    if (-not $Internal -and $parts[-1] -in @('local', 'lan', 'internal', 'intranet', 'corp', 'home', 'localdomain', 'private')) {
        return (& $refuse "'$h' is not a public name, and an EXTERNAL environment can only bind a name Azure can validate in public DNS. Use a public subdomain you own (e.g. pim.<yourdomain>), keep the default name, or run the Manager in a VNet-internal environment for a private name")
    }
    $cert = if ($KeyVaultName -and $KeyVaultCertName) { 'keyvault' } elseif ($PfxPath) { 'pfx' } elseif (-not $Internal) { 'managed' } else { '' }
    if (-not $cert) { return (& $refuse 'an INTERNAL (private-only) environment cannot validate a free managed certificate -- give your own certificate for this name: -KeyVaultName + -KeyVaultCertName, or -PfxPath') }
    $dnsMode = switch ($Dns) {
        'Auto' { if ($Internal) { 'privatezone' } else { 'public' } }
        'PrivateDnsZone' { 'privatezone' }
        'AdDns' { 'addns' }
        default { 'none' }
    }
    if ($dnsMode -in @('privatezone', 'addns') -and -not $Internal) { return (& $refuse 'a private DNS record only makes sense for an INTERNAL environment; an external one is published in your public DNS (-Dns Auto)') }
    if ($dnsMode -in @('privatezone', 'addns') -and "$EnvStaticIp" -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return (& $refuse 'the environment has no static private IP to point the record at') }
    if ($dnsMode -eq 'addns' -and -not $AdDnsServer) { return (& $refuse '-Dns AdDns needs -AdDnsServer') }
    $records = @()
    if ($dnsMode -in @('privatezone', 'addns')) { $records += @{ type = 'A'; zone = $zone; name = $label; value = $EnvStaticIp } }
    if ($dnsMode -eq 'public') {
        $records += @{ type = 'CNAME'; zone = $zone; name = $label; value = $AppFqdn }
        $records += @{ type = 'TXT'; zone = $zone; name = "asuid.$label"; value = $VerificationId }
    }
    $steps = @('hostname-add', "certificate-$cert", 'hostname-bind', "dns-$dnsMode", 'app-hostnames-env', 'easyauth-reply-url')
    return @{
        ok = $true; host = $h; zone = $zone; label = $label; internal = $Internal; certificate = $cert; dns = $dnsMode
        records = $records; steps = $steps
        reason = "custom name $h on a $(if ($Internal) {'private'} else {'public'}) environment: certificate = $cert, DNS = $dnsMode"
    }
}

function Merge-PimManagerHostnames {
    # PURE. The comma-separated PIM_MANAGER_HOSTNAMES value with $Add appended once (case-insensitive, order kept).
    param([string]$Current, [Parameter(Mandatory)][string]$Add)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($x in @("$Current" -split '[,;\s]+') + @($Add)) { $v = "$x".Trim().ToLowerInvariant(); if ($v -and -not $list.Contains($v)) { $list.Add($v) } }
    return ($list -join ',')
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by the tests: functions only

$sub = @('--subscription', $SubscriptionId)
function Az-Json([string]$what, [scriptblock]$cmd) {
    $out = & $cmd 2>$null
    if ($LASTEXITCODE -ne 0) { throw "$what failed (az exit $LASTEXITCODE)" }
    if ("$out".Trim()) { return ($out | ConvertFrom-Json) } else { return $null }
}

Write-Host "== PIM Manager custom host name: $HostName" -ForegroundColor Cyan
$app = Az-Json 'read the Manager app' { az containerapp show @sub -g $ResourceGroup -n $ManagerApp -o json }
$envId = "$($app.properties.managedEnvironmentId)"
$envName = $envId.Split('/')[-1]
$envObj = Az-Json 'read the environment' { az containerapp env show --ids $envId -o json }
$internal = [bool]$envObj.properties.vnetConfiguration.internal
$plan = Get-PimManagerCustomHostPlan -HostName $HostName -Internal $internal -EnvDefaultDomain "$($envObj.properties.defaultDomain)" `
    -EnvStaticIp "$($envObj.properties.staticIp)" -KeyVaultName "$KeyVaultName" -KeyVaultCertName "$KeyVaultCertName" -PfxPath "$PfxPath" `
    -Dns $Dns -AdDnsServer "$AdDnsServer" -AppFqdn "$($app.properties.configuration.ingress.fqdn)" -VerificationId "$($app.properties.customDomainVerificationId)"
if (-not $plan.ok) { throw "refused: $($plan.reason)" }
Write-Host "  $($plan.reason)" -ForegroundColor DarkGray
foreach ($r in $plan.records) { Write-Host ("  DNS  {0,-5} {1}.{2} -> {3}" -f $r.type, $r.name, $r.zone, $r.value) -ForegroundColor White }
if (-not $PSCmdlet.ShouldProcess($ManagerApp, "custom host name $($plan.host)")) { return }

# 1-2. host name + certificate + bind
$hasHost = @($app.properties.configuration.ingress.customDomains | Where-Object { "$($_.name)" -ieq $plan.host }).Count -gt 0
if ($plan.dns -eq 'public' -and -not $PublicDnsReady) {
    Write-Host '  Create the CNAME and TXT records above in your public DNS, then re-run with -PublicDnsReady.' -ForegroundColor Yellow
    return
}
if (-not $hasHost) { Az-Json 'add the host name' { az containerapp hostname add @sub -g $ResourceGroup -n $ManagerApp --hostname $plan.host -o json } | Out-Null }
$certName = ($plan.host -replace '[^a-z0-9-]', '-')
switch ($plan.certificate) {
    'managed' {
        Az-Json 'bind with a managed certificate' { az containerapp hostname bind @sub -g $ResourceGroup -n $ManagerApp --hostname $plan.host --environment $envName --validation-method CNAME -o json } | Out-Null
    }
    default {
        $tmp = $null
        try {
            $pfx = $PfxPath; $pw = $PfxPassword
            if ($plan.certificate -eq 'keyvault') {
                # The certificate's secret half is the PFX (base64); downloaded to a temp file only for the upload, then deleted.
                $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pimcert-" + [guid]::NewGuid().ToString('N') + '.pfx')
                az keyvault secret download @sub --vault-name $KeyVaultName -n $KeyVaultCertName -f $tmp --encoding base64 -o none 2>$null
                if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmp)) { throw "could not read certificate '$KeyVaultCertName' from Key Vault '$KeyVaultName'" }
                $pfx = $tmp
            }
            $pwArgs = @(); if ($pw) { $pwArgs = @('--password', [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))) }
            Az-Json 'upload the certificate to the environment' { az containerapp env certificate upload @sub -g $ResourceGroup -n $envName --certificate-file $pfx --certificate-name $certName @pwArgs -o json } | Out-Null
        } finally { if ($tmp -and (Test-Path $tmp)) { Remove-Item -LiteralPath $tmp -Force } }
        Az-Json 'bind the certificate' { az containerapp hostname bind @sub -g $ResourceGroup -n $ManagerApp --hostname $plan.host --environment $envName --certificate $certName -o json } | Out-Null
    }
}
Write-Host "  bound $($plan.host) ($($plan.certificate) certificate)" -ForegroundColor Green

# 3. DNS
if ($plan.dns -eq 'privatezone') {
    $zrg = if ($PrivateDnsResourceGroup) { $PrivateDnsResourceGroup } else { $ResourceGroup }
    az network private-dns zone create @sub -g $zrg -n $plan.zone -o none --only-show-errors 2>$null | Out-Null
    $have = @(az network private-dns record-set a show @sub -g $zrg -z $plan.zone -n $plan.label --query "aRecords[].ipv4Address" -o tsv 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not ($have.Count -eq 1 -and $have[0] -eq $plan.records[0].value)) {
        if ($have.Count) { az network private-dns record-set a delete @sub -g $zrg -z $plan.zone -n $plan.label --yes -o none 2>$null | Out-Null }
        az network private-dns record-set a add-record @sub -g $zrg -z $plan.zone -n $plan.label -a $plan.records[0].value -o none
    }
    foreach ($v in $LinkVnetIds) {
        $ln = 'link-' + ($v.Split('/')[-1])
        $exists = az network private-dns link vnet show @sub -g $zrg -z $plan.zone -n $ln --query id -o tsv 2>$null
        if (-not "$exists".Trim()) { az network private-dns link vnet create @sub -g $zrg -z $plan.zone -n $ln -v $v -e false -o none }
    }
    Write-Host "  private DNS: $($plan.label).$($plan.zone) -> $($plan.records[0].value) (zone in $zrg, $(@($LinkVnetIds).Count) link(s))" -ForegroundColor Green
} elseif ($plan.dns -eq 'addns') {
    . (Join-Path $PSScriptRoot '_PimSetupShared.ps1')
    Write-PimDnsRecord -DnsServer $AdDnsServer -Fqdn $plan.host -EnvDomain $plan.zone -StaticIp $plan.records[0].value
}

# 4. mail links + known names
$curHosts = "$(@($app.properties.template.containers[0].env | Where-Object { $_.name -eq 'PIM_MANAGER_HOSTNAMES' })[0].value)"
$newHosts = Merge-PimManagerHostnames -Current $curHosts -Add $plan.host
if ($newHosts -ne $curHosts.ToLowerInvariant()) {
    Az-Json 'set PIM_MANAGER_HOSTNAMES' { az containerapp update @sub -g $ResourceGroup -n $ManagerApp --set-env-vars "PIM_MANAGER_HOSTNAMES=$newHosts" -o json } | Out-Null
    Write-Host "  PIM_MANAGER_HOSTNAMES = $newHosts (new revision)" -ForegroundColor Green
}

# 5. Easy Auth reply URL (Graph -- right tenant only)
if (-not $SkipEasyAuth) {
    $active = "$(az account show --query tenantId -o tsv 2>$null)".Trim()
    if ($active -ne $TenantId) { throw "the active az profile is tenant '$active', not '$TenantId' -- set AZURE_CONFIG_DIR to a profile of the environment's tenant (Graph follows the ACTIVE account, not --subscription)" }
    $auth = Az-Json 'read Easy Auth' { az containerapp auth show @sub -g $ResourceGroup -n $ManagerApp -o json }
    $clientId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)"
    if (-not $clientId) { Write-Warning '  Easy Auth has no Entra registration on this app -- no reply URL to add.' }
    else {
        $reply = "https://$($plan.host)/.auth/login/aad/callback"
        $uris = @(az ad app show --id $clientId --query "web.redirectUris" -o json 2>$null | ConvertFrom-Json)
        if ($uris -notcontains $reply) {
            az ad app update --id $clientId --web-redirect-uris @($uris + $reply) -o none
            if ($LASTEXITCODE -ne 0) { throw 'could not add the Easy Auth reply URL' }
            Write-Host "  Easy Auth reply URL added: $reply" -ForegroundColor Green
        }
    }
}
Write-Host "== done: https://$($plan.host)" -ForegroundColor Cyan
