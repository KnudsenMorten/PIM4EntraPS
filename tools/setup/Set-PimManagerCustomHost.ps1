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
         - INTERNAL environment: YOUR certificate for that name -- from Key Vault (-KeyVaultName/-KeyVaultCertName; a PFX
           or a PEM certificate -- PEM is converted to PFX in memory, PowerShell 7 only) or a PFX file (-PfxPath). A free
           managed certificate cannot be validated on a private environment.
         - EXTERNAL environment: a free managed certificate (CNAME validation) once the public records exist
           (-PublicDnsReady, also with -Dns None);
    4. DNS:
         - INTERNAL: an A record -> environment static IP in an EXISTING Azure Private DNS zone in -PrivateDnsResourceGroup:
           the LONGEST zone there that the host name ends with (pim-manager.corp.contoso.local with zone contoso.local ->
           record pim-manager.corp), or -DnsZone. PIM never creates a zone named after your domain (on a linked VNet it
           would answer for ALL of that domain): when none matches, the zone, record and links to create are printed.
           Each -LinkVnetIds network is linked unless it is already linked to the zone under any link name.
           Or -Dns AdDns: PIM does NOT write to your AD DNS (and needs no RSAT module) -- it prints the one host A record
           for your DNS administrator to add, ready-to-paste DNS PowerShell / dnscmd lines and a Resolve-DnsName check.
           The zone is the host name minus its first label unless -DnsZone names it; -AdDnsServer only fills the server
           name into the printed lines (BUG-298);
         - EXTERNAL: prints the CNAME + TXT (asuid) records for your public DNS;
    5. adds the name to PIM_MANAGER_HOSTNAMES on the app (a new revision). Mail links: the ManagerUrl setting switches to
       the custom name only when it is empty or was auto-recorded as the generated address -- on the first signed-in
       Manager page after the new revision (Resolve-PimManagerMailUrl). A ManagerUrl you set yourself is never
       overwritten: change it in Settings;
    6. adds https://<name>/.auth/login/aad/callback to the Manager's Easy Auth app registration (Graph).

  -Remove undoes it: the host name binding is removed from the app, the certificate the script uploaded for that name is
  deleted from the environment (when nothing else uses it), the name leaves PIM_MANAGER_HOSTNAMES and the reply URL leaves
  the Easy Auth registration. DNS is never deleted by PIM: the record to delete is printed (and no zone is ever touched).

  Every call is ARM / Graph REST (no az CLI, 100.41) through ONE session pinned to -TenantId: the Invardia Support app's
  session for that tenant, or the person signing in. The script refuses a session of any other tenant before the first call.

.EXAMPLE
  # internal environment, certificate in Key Vault, private DNS zone in the hub RG, linked to the hub + PIM VNets
  .\Set-PimManagerCustomHost.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup <pim-rg> `
      -HostName pim-manager.corp.local -KeyVaultName kv-x -KeyVaultCertName pim-manager-corp-local `
      -PrivateDnsResourceGroup <dns-rg> -LinkVnetIds <hubVnetId>,<pimVnetId> -WhatIf

.EXAMPLE
  # remove the custom name again (prints the DNS record to delete)
  .\Set-PimManagerCustomHost.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup <pim-rg> -HostName pim-manager.corp.local -Remove

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
    [string]$DnsZone,             # optional: the DNS zone the name lives in (AdDns default: the name minus its first label)
    [string]$AdDnsServer,         # optional: only named in the printed AD DNS lines (BUG-298: PIM never writes AD DNS)
    [switch]$PublicDnsReady,
    [switch]$SkipEasyAuth,
    [switch]$Remove
)
$ErrorActionPreference = 'Stop'

function Get-PimManagerCustomHostPlan {
    <#
      PURE. Decides every step from the facts; refuses what cannot work. Returns @{ ok; reason; host; zone; label;
      zoneGiven; internal; certificate (managed|keyvault|pfx); dns (privatezone|addns|public|none); steps[]; records[] }.
      -DnsZone: the zone the name lives in (must be a proper suffix of the name); without it the zone is ASSUMED to be the
      name minus its first label (privatezone: the caller replaces it with the longest existing private zone).
    #>
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][bool]$Internal,
        [string]$EnvDefaultDomain = '',
        [string]$EnvStaticIp = '',
        [string]$KeyVaultName = '', [string]$KeyVaultCertName = '', [string]$PfxPath = '',
        [ValidateSet('Auto', 'PrivateDnsZone', 'AdDns', 'None')][string]$Dns = 'Auto',
        [string]$AdDnsServer = '',
        [string]$DnsZone = '',
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
    $zoneGiven = $false
    $dz = "$DnsZone".Trim().ToLowerInvariant().TrimEnd('.')
    if ($dz) {
        if ($dz -eq $h -or -not $h.EndsWith('.' + $dz) -or $dz -notmatch '\.') { return (& $refuse "-DnsZone '$dz' is not a parent zone of '$h' (the name must end with .$dz and the zone needs at least two labels)") }
        $zone = $dz; $label = $h.Substring(0, $h.Length - $dz.Length - 1); $zoneGiven = $true
    }
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
        ok = $true; host = $h; zone = $zone; label = $label; zoneGiven = $zoneGiven; internal = $Internal; certificate = $cert; dns = $dnsMode
        records = $records; steps = $steps
        reason = "custom name $h on a $(if ($Internal) {'private'} else {'public'}) environment: certificate = $cert, DNS = $dnsMode"
    }
}

function Select-PimPrivateDnsZoneForHost {
    <#
      PURE. The LONGEST of -Zones (zone names, e.g. from the resource group's private DNS zones) that is a proper parent of
      -HostName, and the record name inside it: pim-manager.corp.contoso.local with zones contoso.local + corp.contoso.local
      -> corp.contoso.local / pim-manager; with only contoso.local -> contoso.local / pim-manager.corp. $null when none fits.
    #>
    param([Parameter(Mandatory)][string]$HostName, [string[]]$Zones = @())
    $h = "$HostName".Trim().ToLowerInvariant().TrimEnd('.')
    $best = ''
    foreach ($z in @($Zones)) {
        $n = "$z".Trim().ToLowerInvariant().TrimEnd('.')
        if (-not $n -or $n -eq $h -or -not $h.EndsWith('.' + $n)) { continue }
        if ($n.Length -gt $best.Length) { $best = $n }
    }
    if (-not $best) { return $null }
    return @{ zone = $best; label = $h.Substring(0, $h.Length - $best.Length - 1) }
}

function Get-PimZoneLinkPlan {
    <#
      PURE. Should -VnetId be linked to the zone, given its existing virtualNetworkLinks (ARM objects: .name,
      .properties.virtualNetwork.id)? A VNet linked under ANY name is left alone ('skip'); otherwise 'create' as
      link-<vnet>, or link-<vnet>-<hash> when that name is taken by a link to another VNet (a PUT would repoint it).
    #>
    param([Parameter(Mandatory)][string]$VnetId, [object[]]$Links = @())
    $v = "$VnetId".Trim().TrimEnd('/')
    foreach ($l in @($Links | Where-Object { $_ })) {
        if ("$($l.properties.virtualNetwork.id)".Trim().TrimEnd('/') -ieq $v) { return @{ action = 'skip'; name = "$($l.name)" } }
    }
    $name = 'link-' + ($v.Split('/')[-1])
    if (@($Links | Where-Object { $_ -and "$($_.name)" -ieq $name }).Count) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hx = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($v.ToLowerInvariant()))[0..3] | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
        $name = "$name-$hx"
    }
    if ($name.Length -gt 80) { $name = $name.Substring(0, 80) }
    return @{ action = 'create'; name = $name }
}

function ConvertTo-PimPfxBase64 {
    <#
      The certificate value to upload (a PFX, base64) from a Key Vault certificate's secret half. -ContentType
      'application/x-pem-file': the value is PEM text (certificate[s] + private key) -> converted to a PFX IN MEMORY with
      .NET (X509Certificate2.CreateFromPem, PowerShell 7 / .NET 5+ only -- Windows PowerShell 5.1 is refused with a clear
      message); the chain certificates in the PEM are kept. Anything else (application/x-pkcs12) is the PFX already.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value, [string]$ContentType = '', [int]$PsMajor = $PSVersionTable.PSVersion.Major)
    if ("$ContentType".Trim() -notmatch '(?i)^application/x-pem-file') { return $Value }
    if ($PsMajor -lt 7) { throw 'the Key Vault certificate is PEM (application/x-pem-file): converting PEM to PFX needs PowerShell 7 -- run this script in pwsh 7, or give the certificate as a PFX (-PfxPath, or a Key Vault certificate with content type PKCS #12).' }
    if ($Value -notmatch '-----BEGIN [A-Z ]*PRIVATE KEY-----') { throw 'the Key Vault PEM certificate has no private key -- the environment needs the certificate WITH its key.' }
    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($Value, $Value)
    $all = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $all.ImportFromPem($Value)
    $out = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    [void]$out.Add($leaf)
    foreach ($c in $all) { if ($c.Thumbprint -ne $leaf.Thumbprint) { [void]$out.Add($c) } }
    $bytes = $out.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
    return [Convert]::ToBase64String($bytes)
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
           "  To use a private zone: create zone '$Zone' (or any parent zone of the name) in '$ResourceGroup', then re-run this",
           "  script -- it picks the longest existing zone the name ends with (or -DnsZone) and adds:",
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

function Remove-PimManagerHostname {
    # PURE. The comma-separated PIM_MANAGER_HOSTNAMES value without $Name (case-insensitive, order and the others kept).
    param([string]$Current, [Parameter(Mandatory)][string]$Name)
    $n = "$Name".Trim().ToLowerInvariant().TrimEnd('.')
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($x in @("$Current" -split '[,;\s]+')) { $v = "$x".Trim().ToLowerInvariant(); if ($v -and $v -ne $n -and -not $list.Contains($v)) { $list.Add($v) } }
    return ($list -join ',')
}

function Get-PimCustomHostRemoveDnsLines {
    # PURE. -Remove: the DNS record(s) the admin deletes (PIM deletes no DNS and never a zone).
    param([Parameter(Mandatory)][string]$HostName, [Parameter(Mandatory)][bool]$Internal)
    $h = "$HostName".Trim().ToLowerInvariant().TrimEnd('.')
    $label = $h.Split('.')[0]
    if ($Internal) {
        return @("DNS: PIM deletes no DNS record and never a zone. Delete this record where you created it",
                 "  (the Azure Private DNS zone the name lives in, or your AD DNS):",
                 "    A     $h",
                 "  then check (expect no answer): Resolve-DnsName $h -Type A")
    }
    return @("DNS: PIM deletes no DNS record. Delete these records in your public DNS:",
             "    CNAME $h",
             "    TXT   asuid.$label (next to $h)")
}

function Get-PchManagerContainer {
    # PURE. The Manager's container on the app -- never [0]: on a sign-in front install [0] is 'signin-front', and
    # PIM_MANAGER_HOSTNAMES written there never reaches the Manager (2026-10-21). By name, else the one that is not the front.
    param([object]$App, [string]$Name = 'ca-pim-manager')
    $cs = @(@($App.properties.template.containers) | Where-Object { $_ })
    $c = @($cs | Where-Object { "$($_.name)" -eq $Name })[0]
    if (-not $c) { $c = @($cs | Where-Object { "$($_.name)" -ne 'signin-front' })[0] }
    return $c
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

Write-Host "== PIM Manager custom host name: $HostName$(if ($Remove) {' (remove)'})" -ForegroundColor Cyan
$app = Get-PimArmAcaApp -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp
if (-not $app) { throw "read the Manager app failed: '$ManagerApp' not found in $ResourceGroup" }
$envId = "$($app.properties.managedEnvironmentId)"
$envName = $envId.Split('/')[-1]
$envObj = Get-PimArmAcaEnv -ResourceId $envId
if (-not $envObj) { throw "read the environment failed: $envId" }
$internal = [bool]$envObj.properties.vnetConfiguration.internal

if ($Remove) {
    # -Remove: binding + certificate off the app, the name out of PIM_MANAGER_HOSTNAMES and the Easy Auth reply URLs.
    # DNS is printed, never deleted; no zone is ever touched.
    $rh = "$HostName".Trim().ToLowerInvariant().TrimEnd('.')
    $bound = @($app.properties.configuration.ingress.customDomains | Where-Object { $_ -and "$($_.name)" -ieq $rh }) | Select-Object -First 1
    $boundCert = if ($bound) { "$($bound.certificateId)".Trim() } else { '' }
    Write-Host "  host name on the app: $(if ($bound) {"bound ($(if ($boundCert) {$boundCert.Split('/')[-1]} else {'no certificate'}))"} else {'not bound'})" -ForegroundColor DarkGray
    foreach ($l in (Get-PimCustomHostRemoveDnsLines -HostName $rh -Internal $internal)) { Write-Host "  $l" -ForegroundColor White }
    $rmTarget = $ManagerApp   # (its own variable: the tests locate the ADD path's gate by its exact text)
    if (-not $PSCmdlet.ShouldProcess($rmTarget, "remove custom host name $rh")) { Write-Host '  preview only -- nothing was changed' -ForegroundColor DarkGray; return }
    if ($bound) {
        Set-PimArmAcaAppConfiguration -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate {
            param($cfg)
            $cfg.ingress | Add-Member -NotePropertyName customDomains -NotePropertyValue @(@($cfg.ingress.customDomains) | Where-Object { $_ -and "$($_.name)" -ine $rh }) -Force
        } | Out-Null
        Write-Host "  removed $rh from the app" -ForegroundColor Green
    }
    # The certificate goes only when it is the one this script uploaded / requested for THIS name and no other name on the
    # app still uses it; Azure refuses (and we only warn) when another app in the environment binds it.
    $ownCert = ($rh -replace '[^a-z0-9-]', '-')
    if ($boundCert -and $boundCert.Split('/')[-1] -ieq $ownCert -and -not @($app.properties.configuration.ingress.customDomains | Where-Object { $_ -and "$($_.name)" -ine $rh -and "$($_.certificateId)" -ieq $boundCert }).Count) {
        try {
            [void](Invoke-PimSetupArm -Method DELETE -Path $boundCert -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk)
            Write-Host "  deleted certificate $ownCert from environment $envName" -ForegroundColor Green
        } catch { Write-Warning "  certificate $ownCert was not deleted ($($_.Exception.Message)) -- another app may still bind it; delete it in the portal when it is free." }
    } elseif ($boundCert) { Write-Host "  certificate $($boundCert.Split('/')[-1]) kept (not created by this script for $rh, or still used by another name)" -ForegroundColor DarkGray }
    $curHosts = "$(@((Get-PchManagerContainer $app).env | Where-Object { $_.name -eq 'PIM_MANAGER_HOSTNAMES' })[0].value)"
    $newHosts = Remove-PimManagerHostname -Current $curHosts -Name $rh
    if (@("$curHosts" -split '[,;\s]+' | Where-Object { "$_".Trim() -ieq $rh }).Count) {
        [void](Set-PimArmAcaAppEnvVars -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ PIM_MANAGER_HOSTNAMES = $newHosts } -ContainerName "$((Get-PchManagerContainer $app).name)")
        Write-Host "  PIM_MANAGER_HOSTNAMES = $(if ($newHosts) {$newHosts} else {'(empty)'}) (new revision)" -ForegroundColor Green
    }
    if (-not $SkipEasyAuth) {
        $auth = Get-PimArmAcaAuthConfig -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp
        $clientId = "$($auth.properties.identityProviders.azureActiveDirectory.registration.clientId)"
        if ($clientId) {
            $reply = "https://$rh/.auth/login/aad/callback"
            $ea = Get-PimGraphApplication -Id $clientId
            if (-not $ea) { throw "the Easy Auth app registration '$clientId' is not readable in tenant '$TenantId'" }
            $uris = @($ea.web.redirectUris | Where-Object { "$_".Trim() })
            if ($uris -contains $reply) {
                Update-PimGraphApplication -Id $clientId -Properties @{ web = @{ redirectUris = @($uris | Where-Object { $_ -ne $reply }) } }
                Write-Host "  Easy Auth reply URL removed: $reply" -ForegroundColor Green
            }
        }
    }
    Write-Host "  mail links: if ManagerUrl in Settings is https://$rh, set it to the address people use now." -ForegroundColor Yellow
    Write-Host "== removed: $rh" -ForegroundColor Cyan
    return
}

$plan = Get-PimManagerCustomHostPlan -HostName $HostName -Internal $internal -EnvDefaultDomain "$($envObj.properties.defaultDomain)" `
    -EnvStaticIp "$($envObj.properties.staticIp)" -KeyVaultName "$KeyVaultName" -KeyVaultCertName "$KeyVaultCertName" -PfxPath "$PfxPath" `
    -Dns $Dns -AdDnsServer "$AdDnsServer" -DnsZone "$DnsZone" -AppFqdn "$($app.properties.configuration.ingress.fqdn)" -VerificationId "$($app.properties.customDomainVerificationId)"
if (-not $plan.ok) { throw "refused: $($plan.reason)" }
Write-Host "  $($plan.reason)" -ForegroundColor DarkGray
$zrg = if ($PrivateDnsResourceGroup) { $PrivateDnsResourceGroup } else { $ResourceGroup }
$zoneExists = $false
if ($plan.dns -eq 'privatezone') {
    # BUG-298 b: find the zone (reads; -WhatIf shows the answer). PIM never CREATES a zone named after the customer's
    # domain. Without -DnsZone: the LONGEST private DNS zone in $zrg that the name ends with, so pim-manager.corp.contoso.local
    # lands in an existing contoso.local as record pim-manager.corp.
    if (-not $plan.zoneGiven) {
        $zl = Invoke-PimSetupArm -Path "/subscriptions/$S/resourceGroups/$zrg/providers/Microsoft.Network/privateDnsZones" -ApiVersion (Get-PimSetupApiVersion privateDns) -All -ErrorAsNull
        $pick = Select-PimPrivateDnsZoneForHost -HostName $plan.host -Zones @(@($zl | Where-Object { $_ }) | ForEach-Object { "$($_.name)" })
        if ($pick) {
            $plan.zone = $pick.zone; $plan.label = $pick.label; $plan.records[0].zone = $pick.zone; $plan.records[0].name = $pick.label
            $zoneExists = $true
        }
    }
    if (-not $zoneExists) { $zoneExists = [bool]"$((Get-PimArmPrivateDnsZone -SubscriptionId $S -ResourceGroup $zrg -Name $plan.zone -ErrorAsNull).name)".Trim() }
}
foreach ($r in $plan.records) { Write-Host ("  DNS  {0,-5} {1}.{2} -> {3}" -f $r.type, $r.name, $r.zone, $r.value) -ForegroundColor White }
if ($plan.dns -eq 'addns') {
    # BUG-298 (owner 2026-10-10 "Manual only"): PIM never writes AD DNS -- print the exact record for the admin (also
    # under -WhatIf), BEFORE anything is touched.
    if (-not $plan.zoneGiven) { Write-Host "  AD DNS zone ASSUMED to be '$($plan.zone)' (the name minus its first label) -- if your zone is a different parent (e.g. a shorter one), re-run with -DnsZone <your zone>." -ForegroundColor Yellow }
    . (Join-Path $PSScriptRoot '_PimSetupShared.ps1')
    Show-PimAdDnsRecord -DnsServer "$AdDnsServer" -Fqdn $plan.host -EnvDomain $plan.zone -StaticIp $plan.records[0].value
} elseif ($plan.dns -eq 'privatezone') {
    if ($zoneExists) { Write-Host "  private DNS zone $($plan.zone) exists in $zrg -- the record $($plan.label) + links will be written there" -ForegroundColor DarkGray }
    else { foreach ($l in (Get-PimPrivateZoneMissingLines -Zone $plan.zone -ResourceGroup $zrg -Label $plan.label -StaticIp $plan.records[0].value -LinkVnetIds $LinkVnetIds)) { Write-Host "  $l" -ForegroundColor Yellow } }
}
if (-not $PSCmdlet.ShouldProcess($ManagerApp, "custom host name $($plan.host)")) { Write-Host '  preview only -- nothing was changed' -ForegroundColor DarkGray; return }

# 1-2. host name + certificate + bind
$hasHost = @($app.properties.configuration.ingress.customDomains | Where-Object { "$($_.name)" -ieq $plan.host }).Count -gt 0
if (-not $plan.internal -and -not $PublicDnsReady) {
    # A public environment's free managed certificate validates through public DNS -- with -Dns Auto AND -Dns None
    # (None only means PIM prints no records for you): stop until the records exist instead of waiting 20 minutes.
    if ($plan.dns -ne 'public') {
        Write-Host ("  The free managed certificate validates through public DNS: CNAME {0} -> {1} and TXT asuid.{0} -> {2}." -f $plan.host, "$($app.properties.configuration.ingress.fqdn)", "$($app.properties.customDomainVerificationId)") -ForegroundColor Yellow
    }
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
        # The certificate's secret half is the PFX (base64) -- or PEM text when the Key Vault certificate's content type is
        # application/x-pem-file, converted to a PFX in memory. Read from Key Vault straight into the upload -- never written
        # to disk. A -PfxPath file is read into memory the same way.
        $pwPlain = ''; if ($PfxPassword) { $pwPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)) }
        if ($plan.certificate -eq 'keyvault') {
            $kvSecret = Invoke-PimSetupRest -Url "https://$KeyVaultName.vault.azure.net/secrets/$KeyVaultCertName`?api-version=$(Get-PimSetupApiVersion keyVaultData)" -Resource 'https://vault.azure.net' -ErrorAsNull
            if (-not "$($kvSecret.value)".Trim()) { throw "could not read certificate '$KeyVaultCertName' from Key Vault '$KeyVaultName' ($($global:PimSetupRestLastError))" }
            $kvType = "$($kvSecret.contentType)".Trim()
            $pfxB64 = ConvertTo-PimPfxBase64 -Value "$($kvSecret.value)" -ContentType $kvType
            if ($kvType -match '(?i)^application/x-pem-file') { $pwPlain = ''; Write-Host '  Key Vault certificate is PEM -- converted to PFX in memory' -ForegroundColor DarkGray }
            $kvSecret = $null
        } else {
            $pfxB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PfxPath).Path))
        }
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
    # links: a VNet already linked to the zone under ANY name is left alone; only an unlinked one gets a link
    $zoneLinks = @(Get-PimArmPrivateDnsLinks -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone)
    foreach ($v in @($LinkVnetIds | Where-Object { "$_".Trim() })) {
        $lp = Get-PimZoneLinkPlan -VnetId $v -Links $zoneLinks
        if ($lp.action -eq 'skip') { Write-Host "  link: $($v.Split('/')[-1]) already linked ($($lp.name))" -ForegroundColor DarkGray; continue }
        Set-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $zrg -ZoneName $plan.zone -Name $lp.name -VnetId $v -RegistrationEnabled $false
        $zoneLinks += [pscustomobject]@{ name = $lp.name; properties = [pscustomobject]@{ virtualNetwork = [pscustomobject]@{ id = $v } } }
    }
    Write-Host "  private DNS: $($plan.label).$($plan.zone) -> $($plan.records[0].value) (zone in $zrg, $(@($LinkVnetIds).Count) link(s))" -ForegroundColor Green
} elseif ($plan.dns -eq 'addns') {
    Write-Host "  AD DNS: PIM wrote nothing -- your DNS administrator adds the record printed above, then runs the Resolve-DnsName check." -ForegroundColor Yellow
}

# 4. known names (mail links follow only an auto-recorded ManagerUrl -- Resolve-PimManagerMailUrl)
$curHosts = "$(@((Get-PchManagerContainer $app).env | Where-Object { $_.name -eq 'PIM_MANAGER_HOSTNAMES' })[0].value)"
$newHosts = Merge-PimManagerHostnames -Current $curHosts -Add $plan.host
if ($newHosts -ne $curHosts.ToLowerInvariant()) {
    [void](Set-PimArmAcaAppEnvVars -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ PIM_MANAGER_HOSTNAMES = $newHosts } -ContainerName "$((Get-PchManagerContainer $app).name)")
    Write-Host "  PIM_MANAGER_HOSTNAMES = $newHosts (new revision)" -ForegroundColor Green
}
Write-Host "  mail links: ManagerUrl switches to https://$($plan.host) on the next signed-in Manager page only if it is empty or was auto-recorded as the generated address; a ManagerUrl set in Settings is never overwritten." -ForegroundColor DarkGray

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
