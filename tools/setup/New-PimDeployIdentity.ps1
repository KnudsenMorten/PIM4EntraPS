#Requires -Version 5.1
<#
.SYNOPSIS
    Create (or find) the DEPLOY identity a first deploy needs, and hand back the three forms of it
    the rest of the toolchain wants: appId, certificate thumbprint, and a PEM on disk for az.

.DESCRIPTION
    🔴 WHY THIS EXISTS. `Invoke-PimDeployAll`'s prereq step refuses without -AdminAppId plus a
    credential, and nothing in the toolchain could MAKE one -- so the very first deploy into a new
    customer tenant stopped on a prerequisite the operator had to hand-build in the portal, in front
    of the customer. That is the only genuinely manual step left in an otherwise one-shot deploy,
    and it is the one that costs the visit.

    IDEMPOTENT. Run it again and it finds the existing registration by display name and reuses it,
    adding a fresh certificate only when the current one is missing or expiring. Safe to put in
    front of every deploy.

    🔒 CERTIFICATE, NEVER A SECRET. A real customer tenant authenticates with a certificate
    (repo-root CLAUDE.md). The private key stays in the caller's certificate store; the PEM written
    for az holds the same key because az has no other way to use one -- protect it accordingly and
    delete it when the engagement ends.

.NOTES
    You must already be signed in to the CUSTOMER's tenant with an identity that can create an app
    registration and assign a role (Global Admin / Privileged Role Admin + Owner). That sign-in is
    the one human step this cannot remove -- everything after it is automated.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [string]$DisplayName = 'PIM4EntraPS Deploy',
    # Where the PEM lands. One file per tenant so two engagements cannot overwrite each other.
    [string]$PemDir,
    # 🔒 LocalMachine, per the repo's identity model: deployment certificates live in
    # `LocalMachine\My` and are found by thumbprint. CurrentUser is the wrong default here -- it is
    # invisible to every other account, so the unattended 03:00 update (which runs as a service
    # account, not as whoever stood the environment up) could not use a certificate placed there,
    # and the failure would surface months later as an update that silently stopped working.
    # Requires elevation; the run says so plainly rather than failing inside New-SelfSignedCertificate.
    [ValidateSet('CurrentUser','LocalMachine')][string]$CertStore = 'LocalMachine',
    [int]$CertYears = 2,
    # The role the deploy identity needs on the subscription. Owner because prereq creates the
    # resource group, VNet, ACR, SQL AND assigns AcrPull to the managed identity -- that last one
    # is a role assignment, which Contributor cannot make.
    [string]$RoleName = 'Owner',
    # 🔴 CROSS-SUBSCRIPTION HUB. Peering is a TWO-SIDED operation: the identity needs
    # Microsoft.Network/virtualNetworks/peer/action on BOTH VNets. Owner on the PIM subscription
    # covers the spoke and nothing else, so when the hub lives in another subscription the peering
    # half fails with an authorization error that reads like a bad VNet name. Pass the hub's full
    # resource id and 'Network Contributor' is granted on it -- scoped to that ONE VNet, never the
    # hub subscription.
    # ⚠️ Your CURRENT sign-in must be able to assign a role there. If it cannot, this is the piece
    # the customer's network owner has to run; the cmdlet is printed so you can hand it over.
    [string]$PeerVnetResourceId,
    [string]$PeerRoleName = 'Network Contributor',
    # 🔴 BUG-155 -- OWNER IS ARM, NOT GRAPH. The infra step resolves every container's managed
    # identity and grants it Graph app roles, which the DEPLOYING identity can only do with
    # Directory.Read.All + AppRoleAssignment.ReadWrite.All + Application.Read.All. Without this
    # switch a public install stops at the infra step with "the DEPLOYING identity was REFUSED".
    # Requires your CURRENT sign-in to be able to grant application permissions (Global
    # Administrator or Privileged Role Administrator). Idempotent: only missing roles are added,
    # nothing the identity already holds is removed. See tools/setup/_PimDeployGraph.ps1.
    [switch]$GrantGraph,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimDeployGraph.ps1')
# 🔴 BUG-158 -- THE GUARDED az. This was the one setup script that called the CLI raw, and it
# captured `az ... 2>&1` straight into VALUES. On a host whose az writes a warning to stderr (the
# 32-bit Python "cryptography" notice, printed on EVERY call and immune to PYTHONWARNINGS because
# az runs python in isolated mode) the warning text BECAME the app id: "reusing app registration
# D:\a\_work\...UserWarning: ..." and then "the service principal for <warning> did not become
# readable". Measured 2026-09-14 on the first public-edition install, step 1. The shadow returns
# STDOUT only, keeps $LASTEXITCODE, and publishes the error text in $global:PimAzLastError.
. (Join-Path $PSScriptRoot '_PimAz.ps1')

function Say ($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Ok  ($m){ Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "    [warn] $m" -ForegroundColor Yellow }

# 🔴 THE PEM HOLDS A PRIVATE KEY FOR AN IDENTITY THAT IS SUBSCRIPTION *OWNER*.
# It was defaulting to %ProgramData%\pim\deploy-certs. ProgramData is machine-wide, and on the
# operator's own build host `BUILTIN\Users` holds Read AND Write on %ProgramData%\pim -- on a box
# ~50 people sign in to. Any one of them could have read that key and become Owner of the
# customer's subscription. Measured 2026-09-11 by reading the live ACL, after the operator asked
# the right question.
# LOCALAPPDATA is per-user and its default ACL is the user + SYSTEM + Administrators. The ACL is
# then set EXPLICITLY anyway (inheritance disabled) rather than trusted, and verified below --
# because "it's under the profile so it must be private" is an assumption, and this is a key.
if (-not "$PemDir".Trim()) { $PemDir = Join-Path $env:LOCALAPPDATA 'pim\deploy-certs' }
$pemPath = Join-Path $PemDir ("deploy-$TenantId.pem")
$cerPath = Join-Path $PemDir ("deploy-$TenantId.cer")
$subject = "CN=pim-deploy-$TenantId"

if (-not $Apply) {
    Say "WOULD ensure app registration '$DisplayName' in tenant $TenantId"
    Say "WOULD ensure a certificate '$subject' in Cert:\$CertStore\My and write $pemPath"
    Say "WOULD ensure role '$RoleName' on /subscriptions/$SubscriptionId"
    if ($GrantGraph) { Say ("WOULD ensure Microsoft Graph application roles: " + ((Get-PimDeployIdentityGraphRoles).Keys -join ', ')) }
    return [pscustomobject]@{ AppId=$null; Thumbprint=$null; PemPath=$pemPath; Created=$false; Planned=$true }
}

$null = New-Item -ItemType Directory -Force -Path $PemDir
# Lock the directory down EXPLICITLY: inheritance off, and only this user, SYSTEM and local
# Administrators. Never rely on the parent's defaults -- a shared host may have loosened them, and
# the failure mode is silent readability of a subscription-Owner key.
try {
    $acl = Get-Acl -LiteralPath $PemDir
    $acl.SetAccessRuleProtection($true, $false)   # protect from inheritance, drop inherited rules
    foreach ($r in @($acl.Access)) { $null = $acl.RemoveAccessRule($r) }
    foreach ($id in @("$env:USERDOMAIN\$env:USERNAME", 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        try {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        } catch { Warn "could not add an ACL entry for '$id': $($_.Exception.Message)" }
    }
    Set-Acl -LiteralPath $PemDir -AclObject $acl
} catch { Warn "could not harden the ACL on $PemDir : $($_.Exception.Message)" }

# VERIFY, never assume -- this is the whole point of the exercise.
try {
    $bad = @((Get-Acl -LiteralPath $PemDir).Access |
             Where-Object { $_.AccessControlType -eq 'Allow' -and
                            "$($_.IdentityReference)" -match 'Everyone|BUILTIN\\Users|Authenticated Users|INTERACTIVE' })
    if ($bad.Count) {
        throw ("$PemDir is readable by $((@($bad | ForEach-Object { "$($_.IdentityReference)" }) | Sort-Object -Unique) -join ', ') " +
               "-- refusing to write a subscription-Owner private key somewhere other users can read it. " +
               "Pass -PemDir <a directory only you can read>.")
    }
    Ok "pem directory locked to this user ($PemDir)"
} catch { throw }

# ---- 1. the app registration -------------------------------------------------------------------
# Find by display name first. Creating a second registration with the same name is legal in Entra
# and produces two identities that look identical in the portal -- a trap worth not setting.
# 🪤 "CANNOT SEE IT" AND "DOES NOT EXIST" LOOK IDENTICAL HERE. `az ad app list` returns an EMPTY
# result -- not an error -- when the signed-in identity cannot read the directory. A deploy SPN has
# Owner on the SUBSCRIPTION (ARM) and usually no Graph rights at all, so the lookup came back empty,
# the script went straight to create, and failed with "Insufficient privileges to complete the
# operation" -- which names neither the identity that lacked them nor the registration that already
# existed under that very display name. Measured at a customer 2026-09-11, mid-deploy.
# So: prove the directory is READABLE before treating "not found" as "absent".
$listOut = az ad app list --display-name $DisplayName --query "[0].appId" -o tsv 2>&1
$listOk  = ($LASTEXITCODE -eq 0)
$appId   = $(if ($listOk) { "$listOut".Trim() } else { '' })
if (-not $listOk) {
    $who = "$(az ad signed-in-user show --query userPrincipalName -o tsv 2>$null)".Trim()
    if (-not $who) { $who = "$(az account show --query 'user.name' -o tsv 2>$null)".Trim() }
    throw ("cannot read app registrations in tenant $TenantId as '$who' -- so whether " +
           "'$DisplayName' already exists is UNKNOWN, and creating one blindly would either fail on " +
           "privileges or make a duplicate. This is normal for a deploy SPN: Owner on the " +
           "subscription is ARM, not Graph. Either sign in as an account that can manage app " +
           "registrations (az login --tenant $TenantId), or skip this step entirely by passing " +
           "-AdminAppId/-AdminCertPem for an identity you already have. az said: $listOut")
}
$created = $false
if ($appId) { Ok "reusing app registration $appId ('$DisplayName')" }
else {
    $appId = "$(az ad app create --display-name $DisplayName --sign-in-audience AzureADMyOrg --query appId -o tsv 2>&1)".Trim()
    if (-not ($appId -match '^[0-9a-f-]{36}$')) {
        throw ("could not create the app registration '$DisplayName' in tenant $TenantId. The " +
               "directory was readable and no registration of that name existed, so this is a " +
               "privilege to CREATE one (Application Administrator, or Application.ReadWrite.All). " +
               "az said: $appId")
    }
    $created = $true
    Ok "created app registration $appId"
}

# The service principal. `az ad sp create` fails if it already exists, which is not an error here.
$spId = "$(az ad sp show --id $appId --query id -o tsv 2>$null)".Trim()
if (-not $spId) {
    # 🪤 Graph is eventually consistent: a registration created a second ago is not always readable
    # yet, and the failure reads as "does not exist" rather than "not yet replicated".
    # 🔴 BUG-159 -- RETRY THE CREATE, NOT JUST THE READ. `az ad sp create` issued seconds after
    # `az ad app create` is itself refused on replication ("The appId ... does not reference a valid
    # application object"); the loop used to re-READ ten times after that single refused create, so
    # nothing ever created the principal. And a re-run could not recover: the registration now
    # "already existed", so the certificate step refused to bind a credential. Measured 2026-09-14,
    # public-edition install step 1.
    for ($i = 0; $i -lt 20 -and -not $spId; $i++) {
        $null = az ad sp create --id $appId 2>&1
        if ($LASTEXITCODE -eq 0) { $spId = "$(az ad sp show --id $appId --query id -o tsv 2>$null)".Trim() }
        if (-not $spId) {
            Say "application not replicated yet -- retrying the service principal create ($([int](($i+1)*5))s)..."
            Start-Sleep -Seconds 5
            $spId = "$(az ad sp show --id $appId --query id -o tsv 2>$null)".Trim()
        }
    }
    if (-not $spId) { throw "the service principal for $appId did not become readable." }
    Ok "created service principal $spId"
} else { Ok "service principal $spId already present" }

# ---- 2. the certificate ------------------------------------------------------------------------
$storePath = "Cert:\$CertStore\My"
$cert = Get-ChildItem $storePath | Where-Object { $_.Subject -eq $subject -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) { Ok "reusing certificate $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" }
else {
    if ($CertStore -eq 'LocalMachine') {
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $elevated) {
            throw ("writing to LocalMachine\My needs an elevated session. Re-run this as Administrator, " +
                   "or pass -CertStore CurrentUser -- but understand what that costs: a CurrentUser " +
                   "certificate is invisible to every other account, including the service account the " +
                   "unattended update runs as.")
        }
    }
    # 🪤 -KeySpec AND -Provider ARE MUTUALLY EXCLUSIVE. -KeySpec belongs to the legacy CSP model;
    # naming a CNG KSP alongside it fails outright with
    #     CertEnroll::CX509Enrollment::_CreateRequest: Provider type not defined.
    #     0x80090017 (NTE_PROV_TYPE_NOT_DEF)
    # Measured here 2026-09-11 while probing three variants. The algorithm and length are stated
    # explicitly and the provider is left to the platform -- that combination produced an
    # exportable key in every variant tested, and is the most portable across hosts.
    $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation $storePath `
              -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 `
              -NotAfter (Get-Date).AddYears($CertYears)
    Ok "created certificate $($cert.Thumbprint) in $storePath"
}
$thumb = $cert.Thumbprint

# The PEM az needs (key + cert, in that order). Written every run so a reused certificate whose PEM
# was cleaned up still produces a usable file.
#
# 🪤 THE OBJECT NEW-SELFSIGNEDCERTIFICATE RETURNS DOES NOT ALWAYS CARRY AN ATTACHED KEY HANDLE, so
# GetRSAPrivateKey on it returns $null even though the key is present and exportable in the store.
# MEASURED live 2026-09-11: "certificate <thumb> has no exportable private key" on a certificate
# that had just been created WITH -KeyExportPolicy Exportable. Re-read it from the store by
# thumbprint, and if that still yields nothing, round-trip through a PFX -- which is the form the
# key is guaranteed to be exportable in when the policy allows it at all.
$cert = Get-Item -LiteralPath (Join-Path $storePath $thumb)
$rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$tmpPfx = $null
if (-not $rsa) {
    Warn 'no key handle on the store object -- round-tripping through a PFX to extract it'
    $pw     = [guid]::NewGuid().ToString('N')
    $sec    = ConvertTo-SecureString $pw -AsPlainText -Force
    $tmpPfx = Join-Path $PemDir "tmp-$thumb.pfx"
    $null = Export-PfxCertificate -Cert $cert -FilePath $tmpPfx -Password $sec -Force
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
             [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    $loaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tmpPfx, $pw, $flags)
    $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($loaded)
    $cert = $loaded
}
if (-not $rsa) { throw "certificate $thumb has no exportable private key in $storePath (PFX round-trip also failed)." }
$pem = "-----BEGIN PRIVATE KEY-----`n" +
       [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), 'InsertLineBreaks') +
       "`n-----END PRIVATE KEY-----`n-----BEGIN CERTIFICATE-----`n" +
       [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') +
       "`n-----END CERTIFICATE-----"
Set-Content -LiteralPath $pemPath -Value $pem -Encoding ascii -NoNewline
if ($tmpPfx) { Remove-Item -LiteralPath $tmpPfx -Force -ErrorAction SilentlyContinue }
Ok "wrote $pemPath"

# ---- 3. bind the certificate to the registration -----------------------------------------------
# 🔴 NEVER TOUCH THE CREDENTIALS OF A REGISTRATION THIS RUN DID NOT CREATE.
# This used `az ad app credential reset --append`. "reset" is the wrong verb to aim at an existing
# identity under any flag: the operator reported credentials being reset in a live tenant, and the
# risk is not worth the convenience -- an app registration shared with anything else loses whatever
# was authenticating with it, silently, and the breakage shows up somewhere entirely different.
#
# So the rule is now structural rather than careful: a credential is added ONLY to a registration
# that did not exist a moment ago and therefore has none to lose. An EXISTING registration is left
# completely alone -- if its certificate is not on this host, that is for the operator to resolve
# by supplying one, not for this script to "fix" by writing to the directory.
$bound = "$(az ad app credential list --id $appId --cert --query "[?customKeyIdentifier=='$thumb'].keyId" -o tsv 2>$null | Select-Object -First 1)".Trim()   # no '|' inside --query: az is az.cmd
if ($bound) { Ok 'certificate already bound to the registration' }
elseif (-not $created) {
    throw ("app registration '$DisplayName' ($appId) already existed, and the certificate on this " +
           "host ($thumb) is not one of its credentials. This script will NOT add a credential to a " +
           "registration it did not create -- that means touching an identity other things may be " +
           "using. Resolve it deliberately: pass -AdminAppId/-AdminCertPem for a credential you " +
           "already hold, or add a certificate to '$DisplayName' yourself and re-run. " +
           "The PEM for this host's certificate is at $pemPath if you want to use THAT one.")
}
else {
    $null = Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT
    # Safe only because $created is true: the registration was made seconds ago by this run and has
    # no other credential that could be revoked.
    $res = az ad app credential reset --id $appId --cert "@$cerPath" --append --years $CertYears 2>&1
    if ($LASTEXITCODE -ne 0) { throw "could not upload the certificate: $res $($global:PimAzLastError)" }
    Remove-Item -LiteralPath $cerPath -Force -ErrorAction SilentlyContinue
    Ok 'certificate bound to the newly-created registration'
}

# ---- 4. the Azure role -------------------------------------------------------------------------
$scope = "/subscriptions/$SubscriptionId"
$has = "$(az role assignment list --subscription $SubscriptionId --assignee $appId --scope $scope --query "[?roleDefinitionName=='$RoleName'].id" -o tsv 2>$null | Select-Object -First 1)".Trim()
if ($has) { Ok "'$RoleName' already assigned on the subscription" }
else {
    # 🪤 A brand-new service principal is not yet visible to the RBAC service: the assignment fails
    # with "PrincipalNotFound" and reads as a rights problem. Retry rather than stop.
    $assigned = $false
    for ($i = 0; $i -lt 12 -and -not $assigned; $i++) {
        $out = az role assignment create --subscription $SubscriptionId --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
                 --role $RoleName --scope $scope 2>&1
        if ($LASTEXITCODE -eq 0) { $assigned = $true; break }
        if ("$out $($global:PimAzLastError)" -notmatch 'PrincipalNotFound|does not exist') { throw "role assignment failed: $out $($global:PimAzLastError)" }
        Say "waiting for the principal to replicate to RBAC ($([int](($i+1)*5))s)..."
        Start-Sleep -Seconds 5
    }
    if (-not $assigned) { throw "could not assign '$RoleName' to $appId on $scope." }
    Ok "'$RoleName' assigned on the subscription"
}

# ---- 4a. BUG-155: Microsoft Graph application roles the deploy itself needs --------------------
$graphGranted = @()
if ($GrantGraph) {
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $graphSpId = "$(az ad sp show --id $graphAppId --query id -o tsv 2>$null)".Trim()
    if (-not ($graphSpId -match '^[0-9a-f-]{36}$')) { throw "could not read the Microsoft Graph service principal in tenant $TenantId." }
    # One GET, then a pure plan: only what is missing is written, nothing is ever removed.
    $existingRaw = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" --query "value[?resourceId=='$graphSpId'].appRoleId" -o tsv 2>&1
    if ($LASTEXITCODE -ne 0) { throw "could not list the deploy identity's app-role assignments: $existingRaw" }
    $existing = @("$existingRaw" -split "\s+" | Where-Object { $_ -match '^[0-9a-f-]{36}$' })
    $plan = Get-PimDeployIdentityGraphPlan -AssignedRoleIds $existing
    if (@($plan).Count -eq 0) { Ok 'Microsoft Graph application roles already granted' }
    foreach ($p in @($plan)) {
        # 🪤 az is az.cmd: a JSON body on the command line is mangled by cmd.exe quoting, and a
        # multi-line one is truncated after line 1. Always hand it a FILE.
        $bodyFile = Join-Path $env:TEMP ("pim-approle-" + [guid]::NewGuid().ToString('N') + '.json')
        try {
            Set-Content -LiteralPath $bodyFile -Value (New-PimAppRoleAssignmentBody -PrincipalId $spId -ResourceId $graphSpId -AppRoleId $p.Id) -Encoding ascii -NoNewline
            $done = $false
            for ($i = 0; $i -lt 12 -and -not $done; $i++) {
                $out = az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignments" `
                         --headers 'Content-Type=application/json' --body "@$bodyFile" -o none 2>&1
                if ($LASTEXITCODE -eq 0) { $done = $true; break }
                $azSaid = "$out $($global:PimAzLastError)"   # the guarded az returns stdout only
                if ($azSaid -match 'Permission being assigned already exists') { $done = $true; break }
                if ($azSaid -match 'Authorization_RequestDenied|Insufficient privileges|Forbidden') {
                    throw ("your sign-in cannot grant application permissions ('$($p.Name)'). Sign in as a " +
                           "Global Administrator or Privileged Role Administrator and re-run -- everything is idempotent. az said: $azSaid")
                }
                Say "waiting for the new principal to replicate before granting $($p.Name) ($([int](($i+1)*5))s)..."
                Start-Sleep -Seconds 5
            }
            if (-not $done) { throw "could not grant Microsoft Graph role '$($p.Name)' to $appId." }
            $graphGranted += $p.Name
            Ok "granted Microsoft Graph application role $($p.Name)"
        } finally { Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue }
    }
}

# ---- 4b. rights on the hub VNet, when it is in another subscription ----------------------------
if ("$PeerVnetResourceId".Trim()) {
    # The hub VNet may live in ANOTHER subscription: scope these calls to the one its id names.
    $peerSubId = @("$PeerVnetResourceId".Trim() -split '/' | Where-Object { $_ })[1]
    if ("$PeerVnetResourceId" -notmatch '(?i)^/subscriptions/[0-9a-f-]{36}/') { throw "PeerVnetResourceId '$PeerVnetResourceId' is not a full /subscriptions/<id>/... resource id." }
    $hubHas = "$(az role assignment list --subscription $peerSubId --assignee $appId --scope $PeerVnetResourceId --query "[?roleDefinitionName=='$PeerRoleName'].id" -o tsv 2>$null | Select-Object -First 1)".Trim()
    if ($hubHas) { Ok "'$PeerRoleName' already assigned on the hub VNet" }
    else {
        $out = az role assignment create --subscription $peerSubId --assignee-object-id $spId --assignee-principal-type ServicePrincipal `
                 --role $PeerRoleName --scope $PeerVnetResourceId 2>&1
        if ($LASTEXITCODE -eq 0) { Ok "'$PeerRoleName' assigned on the hub VNet" }
        else {
            # Do NOT fail the run. The hub usually belongs to a different team, and the deploy can
            # still build everything except the peering -- which the reachability step reports
            # honestly. Hand over the exact command instead of guessing at their process.
            Warn "could not grant '$PeerRoleName' on the hub VNet -- your sign-in has no rights there."
            Warn 'PEERING WILL FAIL until the hub owner runs:'
            Write-Host "      az role assignment create --assignee $appId --role '$PeerRoleName' --scope $PeerVnetResourceId" -ForegroundColor White
        }
    }
}

# ---- 5. prove it can actually sign in -----------------------------------------------------------
# The whole point is that the NEXT step authenticates as this identity. Proving it here means a
# failure is attributed to identity creation, where it belongs, instead of to the deploy.
$probe = Join-Path $env:TEMP "pim-identity-probe-$([guid]::NewGuid().ToString('N'))"
$null = New-Item -ItemType Directory -Force -Path $probe
$prev = $env:AZURE_CONFIG_DIR
try {
    $env:AZURE_CONFIG_DIR = $probe
    $signed = $false
    for ($i = 0; $i -lt 10 -and -not $signed; $i++) {
        $null = az login --service-principal -u $appId --tenant $TenantId --certificate $pemPath --allow-no-subscriptions -o none 2>&1
        if ($LASTEXITCODE -eq 0) { $signed = $true; break }
        Say "credential not replicated yet, retrying ($([int](($i+1)*6))s)..."
        Start-Sleep -Seconds 6
    }
    if (-not $signed) { throw "the identity was created but cannot sign in yet. Wait a minute and re-run -- everything is idempotent." }
    Ok 'the deploy identity signs in'
    if ($GrantGraph) {
        # BUG-155: prove the capability the infra step USES -- a real directory read AS this identity
        # -- not that a grant call returned 200. App-role grants reach new tokens only after
        # replication, so retry, and say so plainly rather than fail an otherwise good identity.
        $read = $false
        for ($i = 0; $i -lt 20 -and -not $read; $i++) {
            # no '&' in the URL: az is az.cmd, and cmd.exe splits the command line at it
            $null = az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=1" -o none 2>&1
            if ($LASTEXITCODE -eq 0) { $read = $true; break }
            Say "Graph read not yet effective for the new roles, retrying ($([int](($i+1)*15))s)..."
            Start-Sleep -Seconds 15
            $null = az login --service-principal -u $appId --tenant $TenantId --certificate $pemPath --allow-no-subscriptions -o none 2>&1
        }
        if ($read) { Ok 'the deploy identity can read the directory (Microsoft Graph)' }
        else { Warn 'Graph roles are granted but not yet effective for this identity; wait a few minutes before the deploy (they are cached per token).' }
    }
} finally {
    $env:AZURE_CONFIG_DIR = $prev
    Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue
}

[pscustomobject]@{
    AppId      = $appId
    Thumbprint = $thumb
    PemPath    = $pemPath
    Created    = $created
    GraphRolesGranted = @($graphGranted)
    Planned    = $false
}
