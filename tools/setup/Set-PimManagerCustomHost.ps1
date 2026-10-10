<#
.SYNOPSIS
  Gives the PIM Manager a custom host name (for example pim-manager.<your domain>) next to its generated Container Apps address: it adds and binds the name with a certificate, writes or prints the DNS records, and adds the name to the Manager's known host names and its sign-in reply URLs.

.DESCRIPTION
  §80.1.
  Operator 2026-09-29: "We need option to add custom dns name to the url, like pim-manager.<internal dns domain>."

  What it does, in order (every step idempotent; -WhatIf shows the plan and changes nothing):
    1. reads the Manager app and its Container Apps environment (internal-only or external, static IP, default domain);
    2. adds the host name to the app;
    3. binds a certificate:
         - INTERNAL environment: YOUR certificate for that name -- from Key Vault (-KeyVaultName/-KeyVaultCertName) or a
           PFX file (-PfxPath). A free managed certificate cannot be validated on a private environment.
         - EXTERNAL environment: a free managed certificate (CNAME validation) once the public records exist;
    4. DNS:
         - INTERNAL: an A record <label> -> environment static IP in the Azure Private DNS zone named after the rest of
           the host name (pim-manager.corp.local -> zone corp.local, record pim-manager) -- ONLY when that zone already
           exists in -PrivateDnsResourceGroup (PIM never creates a zone named after your domain: on a linked VNet it would
           answer for ALL of corp.local; when it is missing, the zone, record and links to create are printed), links
           added for -LinkVnetIds; or -Dns AdDns: PIM does NOT write to your AD DNS (and needs no RSAT module) -- it
           prints the one host A record to add, ready-to-paste DNS PowerShell / dnscmd lines and a Resolve-DnsName check
           (-AdDnsServer only fills the server name into those lines) (BUG-298);
         - EXTERNAL: prints the CNAME + TXT (asuid) records for your public DNS;
    5. adds the name to PIM_MANAGER_HOSTNAMES on the app (mail links then use it -- Resolve-PimManagerMailUrl);
    6. adds https://<name>/.auth/login/aad/callback to the Manager's Easy Auth app registration (Graph).

  Every call is ARM / Graph REST (no az CLI, 100.41) through ONE session pinned to -TenantId: the Invardia Support app's
  session for that tenant, or the person signing in. The script refuses a session of any other tenant before the first call.

.EXAMPLE
  # internal environment, certificate in Key Vault, private DNS zone in the hub RG, linked to the hub + PIM VNets
  .\Set-PimManagerCustomHost.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup <pim-rg> `
      -HostName pim-manager.corp.local -KeyVaultName kv-x -KeyVaultCertName pim-manager-corp-local `
      -PrivateDnsResourceGroup <dns-rg> -LinkVnetIds <hubVnetId>,<pimVnetId> -WhatIf

.LINK
  https://invardia.com/docs/pim/scripts/Set-PimManagerCustomHost/
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
    [string]$AdDnsServer,         # optional: only named in the printed AD DNS lines (BUG-298: PIM never writes AD DNS)
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
    # BUG-298: -Dns AdDns only PRINTS the record (PIM never writes AD DNS), so -AdDnsServer is optional -- it is only named
    # in the printed lines.
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

function Get-PimPrivateZoneMissingLines {
    <#
      PURE (BUG-298 b). -Dns PrivateDnsZone when the zone named after the customer's domain does NOT exist: PIM does not
      create it (linked to a VNet that resolves through Azure DNS, a private zone `corp.local` answers for ALL of
      corp.local, and the customer's other names stop resolving there). These lines tell the admin what to create.
    #>
    param(
        [Parameter(Mandatory)][string]$Zone, [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Label, [Parameter(Mandatory)][string]$StaticIp, [string[]]$LinkVnetIds = @()
    )
    $l = @("PIM did NOT create the Azure Private DNS zone '$Zone' (it does not exist in resource group '$ResourceGroup').",
           "  A private zone named after your domain answers for EVERY name in $Zone on each VNet linked to it -- create it",
           "  only if no other DNS serves $Zone for those VNets. Otherwise add A $Label.$Zone -> $StaticIp in the DNS that does.",
           "  To use a private zone: create zone '$Zone' in '$ResourceGroup', then re-run this script -- it adds:",
           "    A     $Label.$Zone -> $StaticIp")
    foreach ($v in @($LinkVnetIds | Where-Object { "$_".Trim() })) { $l += "    link  $Zone -> $v (registration off)" }
    $l += "  then check (expect $StaticIp): Resolve-DnsName $Label.$Zone -Type A"
    return $l
}

function Merge-PimManagerHostnames {
    # PURE. The comma-separated PIM_MANAGER_HOSTNAMES value with $Add appended once (case-insensitive, order kept).
    param([string]$Current, [Parameter(Mandatory)][string]$Add)
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($x in @("$Current" -split '[,;\s]+') + @($Add)) { $v = "$x".Trim().ToLowerInvariant(); if ($v -and -not $list.Contains($v)) { $list.Add($v) } }
    return ($list -join ',')
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by the tests: functions only
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Set-PimManagerCustomHost'
try {

# 100.41 (framework 12.17 NO-AZ): ARM + Graph REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1),
# pinned to -TenantId -- the Graph step can no longer follow "the active az profile" into another tenant. No az.
$solRootCh = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootCh 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootCh 'engine\_shared\PIM-ArmSetup.ps1') }
$S = "$SubscriptionId".Trim()
$conn = Connect-PimSetupRest -SubscriptionId $S -TenantId $TenantId
if ("$($conn.tenantId)" -ne "$TenantId".Trim().ToLowerInvariant()) { throw "the REST session is for tenant '$($conn.tenantId)', not '$TenantId' -- refusing (Graph must act in the environment's own tenant)." }

Write-Host "== PIM Manager custom host name: $HostName" -ForegroundColor Cyan
$app = Get-PimArmAcaApp -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp
if (-not $app) { throw "read the Manager app failed: '$ManagerApp' not found in $ResourceGroup" }
$envId = "$($app.properties.managedEnvironmentId)"
$envName = $envId.Split('/')[-1]
$envObj = Get-PimArmAcaEnv -ResourceId $envId
if (-not $envObj) { throw "read the environment failed: $envId" }
$internal = [bool]$envObj.properties.vnetConfiguration.internal
$plan = Get-PimManagerCustomHostPlan -HostName $HostName -Internal $internal -EnvDefaultDomain "$($envObj.properties.defaultDomain)" `
    -EnvStaticIp "$($envObj.properties.staticIp)" -KeyVaultName "$KeyVaultName" -KeyVaultCertName "$KeyVaultCertName" -PfxPath "$PfxPath" `
    -Dns $Dns -AdDnsServer "$AdDnsServer" -AppFqdn "$($app.properties.configuration.ingress.fqdn)" -VerificationId "$($app.properties.customDomainVerificationId)"
if (-not $plan.ok) { throw "refused: $($plan.reason)" }
Write-Host "  $($plan.reason)" -ForegroundColor DarkGray
foreach ($r in $plan.records) { Write-Host ("  DNS  {0,-5} {1}.{2} -> {3}" -f $r.type, $r.name, $r.zone, $r.value) -ForegroundColor White }
$zrg = if ($PrivateDnsResourceGroup) { $PrivateDnsResourceGroup } else { $ResourceGroup }
$zoneExists = $false
if ($plan.dns -eq 'addns') {
    # BUG-298 (owner 2026-10-10 "Manual only"): PIM never writes AD DNS -- print the exact record for the admin (also
    # under -WhatIf), BEFORE anything is touched.
    . (Join-Path $PSScriptRoot '_PimSetupShared.ps1')
    Show-PimAdDnsRecord -DnsServer "$AdDnsServer" -Fqdn $plan.host -EnvDomain $plan.zone -StaticIp $plan.records[0].value
} elseif ($plan.dns -eq 'privatezone') {
    # BUG-298 b: read whether the zone exists (a read; -WhatIf shows the answer). PIM never CREATES a zone named after the
    # customer's domain.
    $zoneExists = [bool]"$((Get-PimArmPrivateDnsZone -SubscriptionId $S -ResourceGroup $zrg -Name $plan.zone -ErrorAsNull).name)".Trim()
    if ($zoneExists) { Write-Host "  private DNS zone $($plan.zone) exists in $zrg -- the record + links will be written there" -ForegroundColor DarkGray }
    else { foreach ($l in (Get-PimPrivateZoneMissingLines -Zone $plan.zone -ResourceGroup $zrg -Label $plan.label -StaticIp $plan.records[0].value -LinkVnetIds $LinkVnetIds)) { Write-Host "  $l" -ForegroundColor Yellow } }
}
if (-not $PSCmdlet.ShouldProcess($ManagerApp, "custom host name $($plan.host)")) { Write-Host '  preview only -- nothing was changed' -ForegroundColor DarkGray; return }

# 1-2. host name + certificate + bind
$hasHost = @($app.properties.configuration.ingress.customDomains | Where-Object { "$($_.name)" -ieq $plan.host }).Count -gt 0
if ($plan.dns -eq 'public' -and -not $PublicDnsReady) {
    Write-Host '  Create the CNAME and TXT records above in your public DNS, then re-run with -PublicDnsReady.' -ForegroundColor Yellow
    return
}
if (-not $hasHost) { [void](Set-PimArmAcaAppCustomDomain -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -HostName $plan.host) }   # hostname add
$certName = ($plan.host -replace '[^a-z0-9-]', '-')
switch ($plan.certificate) {
    'managed' {
        # hostname bind --validation-method CNAME: the environment issues a free managed certificate, then the name binds to it.
        $mc = New-PimArmAcaManagedCertificate -SubscriptionId $S -ResourceGroup $ResourceGroup -EnvironmentName $envName -Name $certName -HostName $plan.host -Location "$($envObj.location)"
        [void](Set-PimArmAcaAppCustomDomain -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -HostName $plan.host -CertificateId "$($mc.id)")
    }
    default {
        # The certificate's secret half IS the PFX (base64): read from Key Vault straight into the upload -- never written to
        # disk. A -PfxPath file is read into memory the same way.
        if ($plan.certificate -eq 'keyvault') {
            $pfxB64 = Get-PimKeyVaultSecretValue -VaultName $KeyVaultName -Name $KeyVaultCertName
            if (-not "$pfxB64".Trim()) { throw "could not read certificate '$KeyVaultCertName' from Key Vault '$KeyVaultName' ($($global:PimSetupRestLastError))" }
        } else {
            $pfxB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PfxPath).Path))
        }
        $pwPlain = ''; if ($PfxPassword) { $pwPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)) }
        $ec = Set-PimArmAcaEnvCertificate -SubscriptionId $S -ResourceGroup $ResourceGroup -EnvironmentName $envName -Name $certName -PfxBase64 $pfxB64 -Password $pwPlain -Location "$($envObj.location)"
        $pfxB64 = $null; $pwPlain = $null
        [void](Set-PimArmAcaAppCustomDomain -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -HostName $plan.host -CertificateId "$($ec.id)")   # hostname bind
    }
}
Write-Host "  bound $($plan.host) ($($plan.certificate) certificate)" -ForegroundColor Green

# 3. DNS
if ($plan.dns -eq 'privatezone' -and -not $zoneExists) {
    Write-Host "  private DNS: NOT written -- zone $($plan.zone) does not exist in $zrg (see the lines above; PIM creates no zone named after your domain)." -ForegroundColor Yellow
} elseif ($plan.dns -eq 'privatezone') {
    # read the record before writing it (no blink of a correct record)
    $have = @((Get-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone -Name $plan.label -ErrorAsNull).properties.aRecords | Where-Object { $_ } | ForEach-Object { "$($_.ipv4Address)".Trim() } | Where-Object { $_ })
    if (-not ($have.Count -eq 1 -and $have[0] -eq $plan.records[0].value)) {
        # the record set is written WHOLE: exactly the environment's static IP (what delete + add-record left)
        [void](Set-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone -Name $plan.label -Ipv4 @($plan.records[0].value))
    }
    foreach ($v in $LinkVnetIds) {
        $ln = 'link-' + ($v.Split('/')[-1])
        $exists = "$((Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone -Name $ln -ErrorAsNull).id)"
        if (-not "$exists".Trim()) { Set-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone -Name $ln -VnetId $v -RegistrationEnabled $false }
    }
    Write-Host "  private DNS: $($plan.label).$($plan.zone) -> $($plan.records[0].value) (zone in $zrg, $(@($LinkVnetIds).Count) link(s))" -ForegroundColor Green
} elseif ($plan.dns -eq 'addns') {
    Write-Host "  AD DNS: PIM wrote nothing -- add the record printed above on your DNS server, then run the Resolve-DnsName check." -ForegroundColor Yellow
}

# 4. mail links + known names
$curHosts = "$(@($app.properties.template.containers[0].env | Where-Object { $_.name -eq 'PIM_MANAGER_HOSTNAMES' })[0].value)"
$newHosts = Merge-PimManagerHostnames -Current $curHosts -Add $plan.host
if ($newHosts -ne $curHosts.ToLowerInvariant()) {
    [void](Set-PimArmAcaAppEnvVars -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ PIM_MANAGER_HOSTNAMES = $newHosts } -ContainerName "$($app.properties.template.containers[0].name)")
    Write-Host "  PIM_MANAGER_HOSTNAMES = $newHosts (new revision)" -ForegroundColor Green
}

# 5. Easy Auth reply URL (Graph -- in -TenantId: the REST session above is pinned to it)
if (-not $SkipEasyAuth) {
    $auth = Get-PimArmAcaAuthConfig -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp
    $clientId = "$($auth.properties.identityProviders.azureActiveDirectory.registration.clientId)"
    if (-not $clientId) { Write-Warning '  Easy Auth has no Entra registration on this app -- no reply URL to add.' }
    else {
        $reply = "https://$($plan.host)/.auth/login/aad/callback"
        $ea = Get-PimGraphApplication -Id $clientId
        if (-not $ea) { throw "the Easy Auth app registration '$clientId' is not readable in tenant '$TenantId'" }
        $uris = @($ea.web.redirectUris | Where-Object { "$_".Trim() })
        if ($uris -notcontains $reply) {
            Update-PimGraphApplication -Id $clientId -Properties @{ web = @{ redirectUris = @($uris + $reply) } }
            Write-Host "  Easy Auth reply URL added: $reply" -ForegroundColor Green
        }
    }
}
Write-Host "== done: https://$($plan.host)" -ForegroundColor Cyan
} finally { Stop-PimScriptRun -Script 'Set-PimManagerCustomHost' }
