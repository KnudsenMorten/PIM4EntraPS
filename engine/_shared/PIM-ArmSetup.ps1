#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- what the SETUP / INSTALL scripts need from Azure, over ARM / Graph / data-plane REST.
    No az CLI, no PowerShell module (REQUIREMENTS 100.41, framework DOCS/REQUIREMENTS.md 12.17 NO-AZ).

.DESCRIPTION
    🔒 ONE CONNECT PATH. Every call goes through Invoke-PimSetupRest -> Invoke-PimRest (PIM-Rest.ps1): the token comes
    from PIM-Rest's own client (certificate JWT, the Invardia Support app's secret, a managed identity, or the person's
    browser sign-in, auth code + PKCE), with its paging and its 429 / 5xx backoff. Nothing here mints a token itself and
    nothing here runs `az`. Connect-PimSetupRest only SETS the identity PIM-Rest will use.

    🔑 ONE CALL SHAPE PER WRAPPER. Each wrapper is the REST equivalent of one `az` command the setup scripts used, with the
    same answer shape the script read back (the ARM object -- the scripts pick the property their `--query` used to pick).
    * a probe that `az ... show 2>$null` answered with '' answers $null here: -NotFoundOk turns a 404 into $null,
      -ErrorAsNull turns ANY failure into $null (the reason kept in $global:PimSetupRestLastError) -- the latter only where
      the az call site ignored every failure, so the port does not quietly change what a refusal does;
    * a failure THROWS "<METHOD> <url> -> HTTP <code> : <ARM code> -- <message>" (Invoke-PimRest's BUG-27 shape), and a
      RequestDisallowedByPolicy denial is said once, in the operator's language (Write-PimArmPolicyDenial, the §40.2 rule
      _PimAz.ps1 applied to az's text).

    🧪 TEST SEAM: $global:PIM_SetupRestStub = { param($Method, $Url, $Body, $Resource, $All) ... } replaces the network
    call (and the token) for every wrapper in this file. A stub throws to simulate a failure, exactly as Invoke-PimRest
    does ("... -> HTTP 404 : ResourceNotFound -- ...").

    PS 5.1-safe. Dot-source PIM-Rest.ps1 first (Connect-PimSetupRest loads it when it is missing).
#>

Set-StrictMode -Off

# Pinned api-versions: a floating version turns a silent platform change into a broken install.
$script:PimSetupApi = @{
    resources     = '2021-04-01'
    subscriptions = '2022-12-01'
    network       = '2023-09-01'
    privateDns    = '2020-06-01'
    acr           = '2023-07-01'
    acrPool       = '2019-06-01-preview'
    msi           = '2023-01-31'
    authorization = '2022-04-01'
    sql           = '2021-11-01'
    logAnalytics  = '2022-10-01'
    aca           = '2024-03-01'
    storage       = '2023-01-01'
    keyVault      = '2023-07-01'
    # batch 2: a VNet link's resolutionPolicy (NxDomainRedirect) exists from this version on; the data planes' versions.
    privateDnsLink = '2024-06-01'
    keyVaultData  = '7.4'
    storageData   = '2021-08-06'
}
$script:PimSetupGraph = 'https://graph.microsoft.com/v1.0'
$global:PimSetupApiPins = $script:PimSetupApi

function Get-PimSetupApiVersion {
    param([Parameter(Mandatory)][string]$Kind)
    # A caller's CHILD script (`& .\Set-PimSqlNetworkAccess.ps1`) sees these functions but not this file's script scope: the pins are mirrored to global.
    $pins = if ($script:PimSetupApi) { $script:PimSetupApi } else { $global:PimSetupApiPins }
    if (-not $pins) { throw 'PIM-ArmSetup.ps1 is not loaded in this scope.' }
    $v = $pins[$Kind]
    if (-not $v) { throw "Get-PimSetupApiVersion: no api-version pinned for '$Kind'." }
    return $v
}

# ======================================================================================================================
# identity -- WHO the calls run as (PIM-Rest's globals; no token is minted here)
# ======================================================================================================================

function Get-PimPemCertificateThumbprint {
    <#
      PURE. The SHA-1 thumbprint of the CERTIFICATE block in a PEM (key + cert, the file `az login --certificate` took).
      '' when the file holds no certificate. The private key is never read.
    #>
    param([Parameter(Mandatory)][string]$PemText)
    $m = [regex]::Match("$PemText", '-----BEGIN CERTIFICATE-----(?<b>[\s\S]+?)-----END CERTIFICATE-----')
    if (-not $m.Success) { return '' }
    try {
        $raw = [Convert]::FromBase64String(($m.Groups['b'].Value -replace '\s', ''))
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $raw)
        return "$($c.Thumbprint)".ToUpperInvariant()
    } catch { return '' }
}

function Resolve-PimArmSubscriptionTenant {
    <#
      The tenant a subscription belongs to, WITHOUT a token: ARM answers an anonymous GET with 401 and a
      WWW-Authenticate challenge naming the tenant's authority. This is how `az --subscription X` found the right
      directory for a subscription; a token for the wrong tenant answers InvalidAuthenticationTokenTenant far away.
      Returns the tenant id (lowercase) or ''. Never throws.
      Test seam: $global:PIM_SetupTenantProbe = { param($SubscriptionId) <tenant id> }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId)
    if ($global:PIM_SetupTenantProbe) { try { return "$(& $global:PIM_SetupTenantProbe $SubscriptionId)".Trim().ToLowerInvariant() } catch { return '' } }
    $url = "https://management.azure.com/subscriptions/$SubscriptionId`?api-version=$(Get-PimSetupApiVersion subscriptions)"
    $hdr = ''
    try {
        $null = Invoke-WebRequest -Method GET -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    } catch {
        try { $hdr = "$($_.Exception.Response.Headers['WWW-Authenticate'])" } catch { }
        if (-not $hdr) { try { $hdr = "$(@($_.Exception.Response.Headers.WwwAuthenticate) -join ' ')" } catch { } }
    }
    $m = [regex]::Match($hdr, '(?i)login\.(?:microsoftonline\.com|windows\.net)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')
    if ($m.Success) { return $m.Groups[1].Value.ToLowerInvariant() }
    return ''
}

function Test-PimSetupInteractiveHost {
    # A browser sign-in needs a person at this console; an unattended run must fail fast instead of waiting 5 minutes.
    try { if (-not [Environment]::UserInteractive) { return $false } } catch { }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return $true
}

function Get-PimSupportRestSession {
    <#
      The Invardia Support app's REST session in this shell ($global:InvardiaSupportState, set by Connect-InvardiaSupport.ps1
      without -AzCli) when it covers -TenantId (and -SubscriptionId, when given): @{ appId; secret; tenantId } or $null.
      -State is the test seam. The secret is returned only to hand it to PIM-Rest's token client; it is never printed.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [string]$SubscriptionId, [object]$State)
    $s = if ($PSBoundParameters.ContainsKey('State')) { $State } else { $global:InvardiaSupportState }
    if (-not ($s -is [hashtable]) -or -not $s.Secret -or -not (Test-PimSetupGuid "$($s.AppId)")) { return $null }
    if ("$($s.TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { return $null }
    $subs = @(@($s.Subscriptions) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ("$SubscriptionId".Trim() -and -not ($subs -contains "$SubscriptionId".Trim().ToLowerInvariant())) { return $null }
    $plain = if ($s.Secret -is [System.Security.SecureString]) { [Net.NetworkCredential]::new('', $s.Secret).Password } else { "$($s.Secret)" }
    if (-not "$plain".Trim()) { return $null }
    return @{ appId = "$($s.AppId)".Trim(); secret = $plain; tenantId = "$($s.TenantId)".Trim().ToLowerInvariant() }
}

function Connect-PimSetupRest {
    <#
      Point PIM-Rest's ONE token client at the identity this setup run uses. Returns @{ tenantId; mode; clientId }.
        -ClientId + -ClientSecret     -> 'secret'      (the Invardia Support app, an estate test SPN)
        -ClientId + -CertThumbprint   -> 'certificate' (a certificate in CurrentUser\My / LocalMachine\My)
        -ClientId + -CertificatePem   -> 'certificate' (the PEM's certificate, found BY THUMBPRINT in the store -- both
                                         producers, New-PimDeployIdentity and the MSP build, keep the key there)
        nothing                       -> 'signedIn'    (the person at the keyboard: PIM-Rest's interactive sign-in)
      -TenantId is pinned for every token; without it the subscription's own tenant is resolved (no token needed).
      Sets only PIM-Rest globals; prints nothing secret; never runs az.
    #>
    param(
        [string]$SubscriptionId,
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$CertThumbprint,
        [string]$CertificatePem
    )
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) {
        $rest = Join-Path $PSScriptRoot 'PIM-Rest.ps1'
        if (-not (Test-Path -LiteralPath $rest)) { throw "Connect-PimSetupRest: PIM-Rest.ps1 is not loaded and not found at $rest." }
        . $rest
    }
    $tid = "$TenantId".Trim().ToLowerInvariant()
    if (-not $tid -and "$SubscriptionId".Trim()) { $tid = Resolve-PimArmSubscriptionTenant -SubscriptionId "$SubscriptionId".Trim() }
    if (-not $tid) { throw 'Connect-PimSetupRest: no tenant -- pass -TenantId (the subscription''s tenant could not be resolved).' }
    $cid = "$ClientId".Trim()
    $sec = "$ClientSecret".Trim()
    $thumb = ("$CertThumbprint" -replace '\s', '').ToUpperInvariant()
    if ("$CertificatePem".Trim()) {
        if (-not (Test-Path -LiteralPath $CertificatePem)) { throw "certificate PEM not found: $CertificatePem" }
        $thumb = Get-PimPemCertificateThumbprint -PemText ([IO.File]::ReadAllText($CertificatePem))
        if (-not $thumb) { throw "the PEM $CertificatePem holds no readable CERTIFICATE block." }
        if (-not (Resolve-PimCertificate -Thumbprint $thumb)) {
            throw ("the certificate in $CertificatePem (thumbprint $thumb) is not in CurrentUser\My or LocalMachine\My. " +
                   'Setup signs in with the certificate from the store (no az, no key read from a file): import it there, or pass its thumbprint.')
        }
    }
    if ($sec -and $thumb) { throw 'Connect-PimSetupRest: pass EITHER a client secret OR a certificate, not both.' }
    if (($sec -or $thumb) -and -not $cid) { throw 'Connect-PimSetupRest: a credential needs its -ClientId.' }

    # No credential passed, and the Invardia Support app's REST session (Connect-InvardiaSupport.ps1 WITHOUT -AzCli) covers
    # this tenant: that app IS the agreed support identity (framework 4.1a) -- PIM-Rest signs in as it with its secret.
    $support = $null
    if (-not $cid -and -not $sec -and -not $thumb) { $support = Get-PimSupportRestSession -TenantId $tid -SubscriptionId $SubscriptionId }
    if ($support) { $cid = $support.appId; $sec = $support.secret }

    $global:PIM_TenantId = $tid
    if ($cid -and ($sec -or $thumb)) {
        $global:PIM_ClientId = $cid
        $global:PIM_ClientSecret = $(if ($sec) { $sec } else { $null })
        $global:PIM_CertThumbprint = $(if ($thumb) { $thumb } else { $null })
        $global:PIM_UseManagedIdentity = $null
        $global:PIM_Interactive = $null
        $global:PIM_InteractiveFallback = $null
        $mode = $(if ($support) { 'supportApp' } elseif ($sec) { 'secret' } else { 'certificate' })
    } else {
        foreach ($n in 'PIM_ClientId', 'PIM_ClientSecret', 'PIM_CertThumbprint', 'PIM_UseManagedIdentity') { Set-Variable -Scope Global -Name $n -Value $null -WhatIf:$false }
        $global:PIM_NoManagedIdentity = $true
        # The person signs in in the browser (PIM-Rest: auth code + PKCE) -- only where a person can.
        $global:PIM_InteractiveFallback = [bool](Test-PimSetupInteractiveHost)
        $mode = 'signedIn'
        $cid = ''
    }
    $global:PIM_SetupRestMode = $mode
    return @{ tenantId = $tid; mode = $mode; clientId = $cid }
}

# ======================================================================================================================
# the choke point
# ======================================================================================================================

function Test-PimSetupNotFound {
    # PURE. Is this REST failure text "the thing does not exist" (as opposed to a refusal or an outage)?
    param([AllowEmptyString()][string]$Text)
    return ("$Text" -match '(?i)HTTP 404\b|\bResourceNotFound\b|\bResourceGroupNotFound\b|\bParentResourceNotFound\b|\bNotFound\b|Request_ResourceNotFound|does not exist')
}

function Invoke-PimSetupRest {
    <#
      THE one network call of this file. -Url absolute; -Resource 'arm' | 'graph' | an audience URL.
      -NotFoundOk: a 404 answers $null. -ErrorAsNull: any failure answers $null (reason in $global:PimSetupRestLastError).
    #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Url,
        [object]$Body,
        [string]$Resource = 'arm',
        [switch]$All,
        [switch]$NotFoundOk,
        [switch]$ErrorAsNull,
        [hashtable]$Headers = @{}
    )
    # 🪤 No `return` inside the try/catch: Windows PowerShell 5.1's compiler (it compiles a function after enough calls)
    # fails such a body with "Argument types do not match". The result is assigned and returned once, below.
    $global:PimSetupRestLastError = ''
    $result = $null
    $failure = $null
    try {
        if ($global:PIM_SetupRestStub) { $result = & $global:PIM_SetupRestStub $Method $Url $Body $Resource ([bool]$All) }
        else { $result = Invoke-PimRest -Method $Method -Url $Url -Body $Body -Resource $Resource -All:$All -Headers $Headers }
    } catch { $failure = $_ }
    if ($null -eq $failure) { return $result }
    $msg = "$($failure.Exception.Message)"
    $global:PimSetupRestLastError = $msg
    if ($ErrorAsNull) { return $null }
    if ($NotFoundOk -and (Test-PimSetupNotFound -Text $msg)) { return $null }
    $raw = ''
    try { if ($global:PimLastRestError -and "$($global:PimLastRestError.url)" -eq $Url) { $raw = "$($global:PimLastRestError.body)" } } catch { $raw = '' }
    if (("$msg $raw") -match 'RequestDisallowedByPolicy') { Write-PimArmPolicyDenial -Text "$raw $msg" }
    throw $failure
}

function Invoke-PimSetupArm {
    <# ARM. -Path is '/subscriptions/...' (or a full URL); the api-version is appended unless the path carries one. #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [Parameter(Mandatory)][string]$ApiVersion,
        [switch]$All,
        [switch]$NotFoundOk,
        [switch]$ErrorAsNull
    )
    $url = if ($Path -match '^https?://') { $Path } else { "https://management.azure.com$Path" }
    if ($url -notmatch '[?&]api-version=') { $url += ($(if ($url -match '\?') { '&' } else { '?' }) + "api-version=$ApiVersion") }
    Invoke-PimSetupRest -Method $Method -Url $url -Body $Body -Resource 'arm' -All:$All -NotFoundOk:$NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Invoke-PimSetupGraph {
    <# Microsoft Graph v1.0 (or -Beta). -Path is '/applications/...' or a full URL. #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [object]$Body,
        [switch]$All,
        [switch]$Beta,
        [switch]$NotFoundOk,
        [switch]$ErrorAsNull,
        [hashtable]$Headers = @{}
    )
    $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { $script:PimSetupGraph }
    if (-not $base) { $base = 'https://graph.microsoft.com/v1.0' }
    $url = if ($Path -match '^https?://') { $Path } else { "$base$Path" }
    Invoke-PimSetupRest -Method $Method -Url $url -Body $Body -Resource 'graph' -All:$All -NotFoundOk:$NotFoundOk -ErrorAsNull:$ErrorAsNull -Headers $Headers
}

function Write-PimArmPolicyDenial {
    <#
      §40.2 -- say a RequestDisallowedByPolicy denial ONCE per assignment, in the operator's language: the target, the
      assignment, the field it evaluated, what this deploy set and what the policy wants, and the action. Anything not
      recognised is left to the thrown error (never swallowed). The ARM error JSON carries the same policyAssignment /
      evaluatedExpressions blocks az printed, so the reading is the one _PimAz.ps1 applied to az's text.
    #>
    param([string]$Text)
    if (-not $script:PimSetupPolicySeen) { $script:PimSetupPolicySeen = @{} }
    $t = "$Text"
    $target = if ($t -match '(?i)"target"\s*:\s*"([^"]+)"') { $Matches[1] } elseif ($t -match 'Target:\s*([^\s,]+)') { $Matches[1] } else { '(resource)' }
    $assignments = @([regex]::Matches($t, '"policyAssignment"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
    $definitions = @([regex]::Matches($t, '"policyDefinition"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
    if (-not $assignments) { $assignments = @('(unnamed assignment)') }
    Write-Host ("    BLOCKED BY AZURE POLICY: {0}" -f $target) -ForegroundColor Red
    for ($i = 0; $i -lt $assignments.Count; $i++) {
        $a = $assignments[$i]
        $d = if ($i -lt $definitions.Count) { $definitions[$i] } else { '' }
        if ($script:PimSetupPolicySeen.ContainsKey($a)) { Write-Host ("      {0} -- same policy as before, see above" -f $a) -ForegroundColor DarkGray; continue }
        $script:PimSetupPolicySeen[$a] = $true
        Write-Host ("      assignment : {0}{1}" -f $a, $(if ($d) { "  ($d)" } else { '' })) -ForegroundColor Red
        $field = $null; $saw = $null; $wanted = $null
        foreach ($m in [regex]::Matches($t, '"expression"\s*:\s*"([^"]+)"[\s\S]{0,200}?"expressionValue"\s*:\s*"([^"]+)"[\s\S]{0,120}?"targetValue"\s*:\s*(?:"([^"]+)"|\[([^\]]*)\])')) {
            if ($m.Groups[1].Value -eq 'type') { continue }
            $field = $m.Groups[1].Value; $saw = $m.Groups[2].Value
            $wanted = if ($m.Groups[3].Success) { $m.Groups[3].Value } else { ($m.Groups[4].Value -replace '"', '' -replace '\s+', ' ').Trim() }
            break
        }
        $allowed = if ($t -match '"listOfAllowedLocations"\s*:\s*\[\s*([^\]]+)\]') { ($Matches[1] -replace '"', '' -replace '\s+', ' ').Trim() } else { $null }
        if ($field) {
            Write-Host ("      field      : {0}" -f $field) -ForegroundColor Yellow
            Write-Host ("      this deploy sets '{0}'; the policy requires '{1}'" -f $saw, $wanted) -ForegroundColor Yellow
        }
        if ($allowed) { Write-Host ("      -> re-run with -Location {0}" -f ($allowed -split ',')[0].Trim()) -ForegroundColor Yellow }
        else {
            Write-Host  '      -> exempt THIS assignment for the subscription, or change the deploy to satisfy it' -ForegroundColor Yellow
            Write-Host  '         (exempt by ASSIGNMENT NAME above -- a policy display name can describe a' -ForegroundColor DarkGray
            Write-Host  '          different resource type than the field it actually evaluates)' -ForegroundColor DarkGray
        }
    }
}

function Wait-PimArmProvisioned {
    <#
      Poll a resource until properties.provisioningState is terminal. Returns the final state ('Succeeded', 'Failed',
      'Canceled', 'TimedOut(<last>)', or 'NotFound'). A create that returns as soon as ARM accepts it is not done (BUG-44).
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [int]$TimeoutSeconds = 900, [int]$PollSeconds = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $state = 'Unknown'
    while ($true) {
        $o = Invoke-PimSetupArm -Path $Path -ApiVersion $ApiVersion -NotFoundOk
        if ($null -eq $o) { $state = 'NotFound' }
        else {
            $state = "$($o.properties.provisioningState)"
            if (-not $state) { return 'Succeeded' }   # a resource type that carries no provisioningState is done when it reads back
            if ($state -notmatch '(?i)^(InProgress|Creating|Updating|Accepted|Provisioning|Waiting|Deleting|Running|ScheduledForDelete)$') { return $state }
        }
        if ((Get-Date) -ge $deadline) { return "TimedOut($state)" }
        Start-Sleep -Seconds $PollSeconds
    }
}

# ======================================================================================================================
# ids
# ======================================================================================================================

function Get-PimArmResourceId {
    <# PURE. /subscriptions/<s>/resourceGroups/<rg>/providers/<Type>/<name>[/<child...>] #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Name, [string]$Child)
    $id = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/$Type/$Name"
    if ("$Child".Trim()) { $id += '/' + "$Child".Trim().TrimStart('/') }
    return $id
}

function Get-PimArmIdPart {
    <# PURE. A named segment of an ARM id ('resourceGroups' -> the group, 'subscriptions' -> the subscription). #>
    param([string]$Id, [Parameter(Mandatory)][string]$Segment)
    $m = [regex]::Match("$Id", "(?i)/$([regex]::Escape($Segment))/([^/]+)")
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

# ======================================================================================================================
# subscription / providers / resource groups / tags
# ======================================================================================================================

function Get-PimArmSubscription {
    <# az account show --subscription X : { subscriptionId; tenantId; displayName; state } or $null. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId" -ApiVersion (Get-PimSetupApiVersion subscriptions) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimArmProviderState {
    <# az provider show --namespace N --query registrationState -> 'Registered' | 'NotRegistered' | ... | '' #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Namespace)
    $p = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/providers/$Namespace" -ApiVersion (Get-PimSetupApiVersion resources) -ErrorAsNull
    if ($p) { return "$($p.registrationState)" }
    return ''
}

function Register-PimArmProvider {
    <# az provider register --namespace N [--wait] -> the final registrationState. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Namespace, [switch]$Wait, [int]$TimeoutSeconds = 600)
    [void](Invoke-PimSetupArm -Method POST -Path "/subscriptions/$SubscriptionId/providers/$Namespace/register" -ApiVersion (Get-PimSetupApiVersion resources))
    $state = Get-PimArmProviderState -SubscriptionId $SubscriptionId -Namespace $Namespace
    if (-not $Wait) { return $state }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($state -ne 'Registered' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        $state = Get-PimArmProviderState -SubscriptionId $SubscriptionId -Namespace $Namespace
    }
    return $state
}

function Get-PimArmResourceGroup {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/resourcegroups/$Name" -ApiVersion (Get-PimSetupApiVersion resources) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmResourceGroup {
    <# az group create -n N -l L [--tags]: PUT (idempotent; an existing group keeps its location). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [hashtable]$Tags)
    $cur = Get-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $Name
    $body = @{ location = $(if ($cur) { "$($cur.location)" } else { $Location }) }
    if ($Tags) { $body.tags = $Tags } elseif ($cur -and $cur.tags) { $body.tags = $cur.tags }
    Invoke-PimSetupArm -Method PUT -Path "/subscriptions/$SubscriptionId/resourcegroups/$Name" -Body $body -ApiVersion (Get-PimSetupApiVersion resources)
}

function Merge-PimArmTags {
    <# az tag update --resource-id X --operation Merge --tags k=v ... #>
    param([Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][hashtable]$Tags)
    $body = @{ operation = 'Merge'; properties = @{ tags = $Tags } }
    Invoke-PimSetupArm -Method PATCH -Path ("$ResourceId".TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -Body $body -ApiVersion (Get-PimSetupApiVersion resources)
}

# ======================================================================================================================
# network: VNet, subnet, peering, private endpoint, private DNS
# ======================================================================================================================

function Get-PimArmVnet {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $Name) -ApiVersion (Get-PimSetupApiVersion network) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmVnet {
    <#
      az network vnet create -g RG -n N -l L --address-prefixes CIDR [--subnet-name S --subnet-prefixes P]
      PUT then wait. An EXISTING VNet is not rewritten (a PUT without its subnets would delete them) -- it is returned.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string[]]$AddressPrefixes, [string]$SubnetName, [string]$SubnetPrefix, [hashtable]$Tags)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $Name
    $cur = Get-PimArmVnet -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if ($cur) { return $cur }
    $body = @{ location = $Location; properties = @{ addressSpace = @{ addressPrefixes = @($AddressPrefixes) } } }
    if ("$SubnetName".Trim() -and "$SubnetPrefix".Trim()) { $body.properties.subnets = @(@{ name = $SubnetName; properties = @{ addressPrefix = $SubnetPrefix } }) }
    if ($Tags) { $body.tags = $Tags }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion network))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion network))
    Get-PimArmVnet -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmSubnet {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VnetName, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "subnets/$Name") -ApiVersion (Get-PimSetupApiVersion network) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmSubnet {
    <#
      az network vnet subnet create|update --address-prefixes P [--delegations D] [--private-endpoint-network-policies X]
      READ-MODIFY-WRITE: an existing subnet keeps every property not named here (NSG, route table, service endpoints).
      -Delegation '' leaves delegations as they are; a value sets exactly that one delegation.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VnetName,
          [Parameter(Mandatory)][string]$Name, [string]$AddressPrefix, [string]$Delegation, [string]$PrivateEndpointNetworkPolicies,
          # az network vnet subnet update --service-endpoints A B : the list is written AS GIVEN (REPLACES it, as the flag
          # did) -- a caller that only means to add reads the current list and passes the union.
          [string[]]$ServiceEndpoints)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "subnets/$Name"
    $cur = Get-PimArmSubnet -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $Name
    $props = @{}
    if ($cur -and $cur.properties) { foreach ($p in $cur.properties.PSObject.Properties) { if ($p.Name -notin @('provisioningState', 'ipConfigurations', 'purpose', 'privateEndpoints', 'serviceAssociationLinks', 'resourceNavigationLinks', 'ipConfigurationProfiles')) { $props[$p.Name] = $p.Value } } }
    if ("$AddressPrefix".Trim()) { $props.addressPrefix = "$AddressPrefix".Trim(); $props.Remove('addressPrefixes') }
    if ("$Delegation".Trim()) { $props.delegations = @(@{ name = 'delegation'; properties = @{ serviceName = "$Delegation".Trim() } }) }
    if ("$PrivateEndpointNetworkPolicies".Trim()) { $props.privateEndpointNetworkPolicies = "$PrivateEndpointNetworkPolicies".Trim() }
    if ($PSBoundParameters.ContainsKey('ServiceEndpoints')) { $props.serviceEndpoints = @(@($ServiceEndpoints) | Where-Object { "$_".Trim() } | ForEach-Object { @{ service = "$_".Trim() } }) }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ properties = $props } -ApiVersion (Get-PimSetupApiVersion network))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion network))
    Get-PimArmSubnet -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $Name
}

function Get-PimArmVnetPeering {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VnetName, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "virtualNetworkPeerings/$Name") -ApiVersion (Get-PimSetupApiVersion network) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmVnetPeering {
    <# az network vnet peering create --remote-vnet ID --allow-vnet-access [--allow-forwarded-traffic] ... #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$VnetName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$RemoteVnetId,
          [bool]$AllowVnetAccess = $true, [bool]$AllowForwardedTraffic = $false, [bool]$AllowGatewayTransit = $false, [bool]$UseRemoteGateways = $false)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "virtualNetworkPeerings/$Name"
    $body = @{ properties = @{ remoteVirtualNetwork = @{ id = $RemoteVnetId }; allowVirtualNetworkAccess = $AllowVnetAccess
                               allowForwardedTraffic = $AllowForwardedTraffic; allowGatewayTransit = $AllowGatewayTransit; useRemoteGateways = $UseRemoteGateways } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion network))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion network))
    Get-PimArmVnetPeering -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $Name
}

function Get-PimArmPrivateEndpoint {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateEndpoints' $Name) -ApiVersion (Get-PimSetupApiVersion network) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmPrivateEndpoint {
    <# az network private-endpoint create --vnet-name V --subnet S --private-connection-resource-id R --group-id G --connection-name C -l L #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId, [Parameter(Mandatory)][string]$TargetResourceId,
          [Parameter(Mandatory)][string]$GroupId, [string]$ConnectionName)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateEndpoints' $Name
    $cn = if ("$ConnectionName".Trim()) { "$ConnectionName".Trim() } else { "$Name-conn" }
    $body = @{ location = $Location; properties = @{ subnet = @{ id = $SubnetId }
               privateLinkServiceConnections = @(@{ name = $cn; properties = @{ privateLinkServiceId = $TargetResourceId; groupIds = @($GroupId) } }) } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion network))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion network))
    Get-PimArmPrivateEndpoint -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Set-PimArmPrivateDnsZoneGroup {
    <# az network private-endpoint dns-zone-group create --endpoint-name E -n G --private-dns-zone ZONEID --zone-name Z #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$EndpointName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ZoneId, [string]$ConfigName)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateEndpoints' $EndpointName "privateDnsZoneGroups/$Name"
    $cfg = if ("$ConfigName".Trim()) { "$ConfigName".Trim() } else { (("$ZoneId" -split '/')[-1] -replace '\.', '-') }
    $body = @{ properties = @{ privateDnsZoneConfigs = @(@{ name = $cfg; properties = @{ privateDnsZoneId = $ZoneId } }) } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion network))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion network))
}

function Get-PimArmPrivateDnsZone {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $Name) -ApiVersion (Get-PimSetupApiVersion privateDns) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmPrivateDnsZone {
    <# az network private-dns zone create -n Z (idempotent: an existing zone is returned untouched). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $cur = Get-PimArmPrivateDnsZone -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if ($cur) { return $cur }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $Name
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = 'global' } -ApiVersion (Get-PimSetupApiVersion privateDns))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion privateDns))
    Get-PimArmPrivateDnsZone -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmPrivateDnsLinks {
    <# az network private-dns link vnet list -z Z #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName, [switch]$ErrorAsNull)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName 'virtualNetworkLinks') -ApiVersion (Get-PimSetupApiVersion privateDns) -All -NotFoundOk -ErrorAsNull:$ErrorAsNull
    return @($r | Where-Object { $_ })
}

function New-PimArmPrivateDnsLink {
    <# az network private-dns link vnet create -z Z -n N --virtual-network VNETID --registration-enabled false #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$VnetId, [bool]$RegistrationEnabled = $false)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "virtualNetworkLinks/$Name"
    $body = @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $VnetId }; registrationEnabled = $RegistrationEnabled } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion privateDns))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion privateDns))
}

function Get-PimArmPrivateDnsARecords {
    <# az network private-dns record-set a list -z Z : the A record sets (each .name, .properties.aRecords[].ipv4Address). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName, [switch]$ErrorAsNull)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName 'A') -ApiVersion (Get-PimSetupApiVersion privateDns) -All -NotFoundOk -ErrorAsNull:$ErrorAsNull
    return @($r | Where-Object { $_ })
}

function Get-PimArmPrivateDnsARecord {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "A/$Name") -ApiVersion (Get-PimSetupApiVersion privateDns) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmPrivateDnsARecord {
    <# az network private-dns record-set a add-record (the set is written WHOLE: exactly -Ipv4 addresses, -Ttl). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Ipv4, [int]$Ttl = 3600)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "A/$Name"
    $body = @{ properties = @{ ttl = $Ttl; aRecords = @(@($Ipv4) | Where-Object { "$_".Trim() } | ForEach-Object { @{ ipv4Address = "$_".Trim() } }) } }
    Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion privateDns)
}

function Remove-PimArmPrivateDnsARecord {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName, [Parameter(Mandatory)][string]$Name)
    Invoke-PimSetupArm -Method DELETE -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "A/$Name") -ApiVersion (Get-PimSetupApiVersion privateDns) -NotFoundOk
}

# ======================================================================================================================
# Log Analytics
# ======================================================================================================================

function Get-PimArmLogAnalytics {
    <# az monitor log-analytics workspace show : .properties.customerId is az's top-level customerId. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.OperationalInsights/workspaces' $Name) -ApiVersion (Get-PimSetupApiVersion logAnalytics) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmLogAnalytics {
    <# az monitor log-analytics workspace create (PerGB2018, 30 days -- the CLI's defaults). Existing: returned untouched. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [int]$RetentionDays = 30)
    $cur = Get-PimArmLogAnalytics -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if ($cur) { return $cur }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.OperationalInsights/workspaces' $Name
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = $Location; properties = @{ sku = @{ name = 'PerGB2018' }; retentionInDays = $RetentionDays } } -ApiVersion (Get-PimSetupApiVersion logAnalytics))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion logAnalytics))
    Get-PimArmLogAnalytics -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmLogAnalyticsKey {
    <# az monitor log-analytics workspace get-shared-keys --query primarySharedKey -> the key, or '' #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $k = Invoke-PimSetupArm -Method POST -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.OperationalInsights/workspaces' $Name 'sharedKeys') -Body @{} -ApiVersion (Get-PimSetupApiVersion logAnalytics) -ErrorAsNull
    if ($k) { return "$($k.primarySharedKey)" }
    return ''
}

function Invoke-PimLogAnalyticsQuery {
    <#
      A KQL query against a workspace (its customerId) -- the data-plane REST az's `logs show` streams replaced by. Returns
      rows as objects (column name -> value). Never throws: @() on any failure (diagnostics only).
    #>
    param([Parameter(Mandatory)][string]$WorkspaceCustomerId, [Parameter(Mandatory)][string]$Query, [string]$Timespan = 'P1D')
    $r = Invoke-PimSetupRest -Method POST -Url "https://api.loganalytics.io/v1/workspaces/$WorkspaceCustomerId/query" -Resource 'https://api.loganalytics.io' -Body @{ query = $Query; timespan = $Timespan } -ErrorAsNull
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($r.tables | Select-Object -First 1)) {
        $cols = @($t.columns | ForEach-Object { "$($_.name)" })
        foreach ($row in @($t.rows)) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $cols.Count; $i++) { $o[$cols[$i]] = @($row)[$i] }
            $out.Add([pscustomobject]$o)
        }
    }
    return @($out.ToArray())
}

# ======================================================================================================================
# Azure Container Registry (control plane + the registry's own data plane)
# ======================================================================================================================

function Find-PimArmAcr {
    <# az acr show -n NAME (no -g): the registry called NAME anywhere in the subscription, or $null. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Name)
    $all = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/providers/Microsoft.ContainerRegistry/registries" -ApiVersion (Get-PimSetupApiVersion acr) -All -ErrorAsNull
    return (@($all | Where-Object { $_ -and "$($_.name)" -ieq "$Name".Trim() }) | Select-Object -First 1)
}

function Get-PimArmAcr {
    <# az acr show [-g RG] -n NAME. Without -ResourceGroup the subscription is searched (as az does). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    if (-not "$ResourceGroup".Trim()) { return (Find-PimArmAcr -SubscriptionId $SubscriptionId -Name $Name) }
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ContainerRegistry/registries' $Name) -ApiVersion (Get-PimSetupApiVersion acr) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmAcr {
    <# az acr create --sku S [--admin-enabled false] (existing: returned untouched). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [string]$Sku = 'Basic', [hashtable]$Properties)
    $cur = Get-PimArmAcr -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if ($cur) { return $cur }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ContainerRegistry/registries' $Name
    $props = @{ adminUserEnabled = $false }
    if ($Properties) { foreach ($k in $Properties.Keys) { $props[$k] = $Properties[$k] } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = $Location; sku = @{ name = $Sku }; properties = $props } -ApiVersion (Get-PimSetupApiVersion acr))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion acr))
    Get-PimArmAcr -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Update-PimArmAcr {
    <# az acr update --sku S | --public-network-enabled ... : PATCH of the named parts only. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [string]$Sku, [hashtable]$Properties)
    $body = @{}
    if ("$Sku".Trim()) { $body.sku = @{ name = "$Sku".Trim() } }
    if ($Properties) { $body.properties = $Properties }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ContainerRegistry/registries' $Name
    [void](Invoke-PimSetupArm -Method PATCH -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion acr))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion acr))
    Get-PimArmAcr -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmAcrCredential {
    <# az acr credential show : @{ username; password } (passwords[0]) or $null. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceId)
    $c = Invoke-PimSetupArm -Method POST -Path ("$ResourceId".TrimEnd('/') + '/listCredentials') -Body @{} -ApiVersion (Get-PimSetupApiVersion acr) -ErrorAsNull
    if (-not $c) { return $null }
    return @{ username = "$($c.username)"; password = "$(@($c.passwords)[0].value)" }
}

function Get-PimArmAcrAgentPool {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Registry, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ContainerRegistry/registries' $Registry "agentPools/$Name") -ApiVersion (Get-PimSetupApiVersion acrPool) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmAcrAgentPool {
    <# az acr agentpool create -r R -n N --tier T --subnet-id S [--count C] ; waits for provisioning. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Registry,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [string]$Tier = 'S1', [int]$Count = 1, [string]$SubnetId, [int]$TimeoutSeconds = 1800)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ContainerRegistry/registries' $Registry "agentPools/$Name"
    $props = @{ count = $Count; tier = $Tier; os = 'Linux' }
    if ("$SubnetId".Trim()) { $props.virtualNetworkSubnetResourceId = "$SubnetId".Trim() }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = $Location; properties = $props } -ApiVersion (Get-PimSetupApiVersion acrPool))
    Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion acrPool) -TimeoutSeconds $TimeoutSeconds
}

function Get-PimAcrDataToken {
    <#
      A registry access token for ONE repository (pull scope), over the registry's own OAuth2 endpoints: the ARM token
      PIM-Rest issues is exchanged for an ACR refresh token, then for a repository-scoped access token. No az, no docker.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repository, [string]$TenantId)
    $aad = Get-PimRestToken -Resource 'arm'
    $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { Get-PimTokenTenantId -Token $aad }
    $ex = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/exchange" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        grant_type = 'access_token'; service = $LoginServer; tenant = $tid; access_token = $aad }
    $tk = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        grant_type = 'refresh_token'; service = $LoginServer; scope = "repository:$Repository`:pull"; refresh_token = "$($ex.refresh_token)" }
    return "$($tk.access_token)"
}

function Invoke-PimAcrData {
    # One GET on the registry's data plane. Test seam: $global:PIM_SetupAcrStub = { param($LoginServer, $Path) ... }.
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string]$Path)
    if ($global:PIM_SetupAcrStub) { return (& $global:PIM_SetupAcrStub $LoginServer $Path) }
    $tok = Get-PimAcrDataToken -LoginServer $LoginServer -Repository $Repository
    Invoke-RestMethod -Method GET -Uri "https://$LoginServer$Path" -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60
}

function Get-PimAcrRepositoryTags {
    <#
      az acr repository show-tags -n R --repository REPO -o tsv : every tag name (paged with `last`), @() when the
      repository or the registry cannot be read (the az call sites treated that as "no tags").
    #>
    param([Parameter(Mandatory)][string]$Registry, [Parameter(Mandatory)][string]$Repository, [string]$LoginServer)
    $ls = if ("$LoginServer".Trim()) { "$LoginServer".Trim() } else { "$("$Registry".Trim().ToLowerInvariant()).azurecr.io" }
    $tags = New-Object System.Collections.Generic.List[string]
    $last = ''
    try {
        for ($page = 0; $page -lt 100; $page++) {
            $p = "/acr/v1/$Repository/_tags?n=1000" + $(if ($last) { "&last=$([uri]::EscapeDataString($last))" } else { '' })
            $r = Invoke-PimAcrData -LoginServer $ls -Repository $Repository -Path $p
            $names = @(@($r.tags) | Where-Object { $_ } | ForEach-Object { "$($_.name)" } | Where-Object { $_ })
            foreach ($n in $names) { $tags.Add($n) }
            if ($names.Count -lt 1000) { break }
            $last = $names[-1]
        }
    } catch { $global:PimSetupRestLastError = "$($_.Exception.Message)"; return @() }
    return @($tags.ToArray())
}

function Get-PimAcrImageDigest {
    <# az acr repository show --image REPO:TAG --query digest : 'sha256:...' or ''. #>
    param([Parameter(Mandatory)][string]$Registry, [Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string]$Tag, [string]$LoginServer)
    $ls = if ("$LoginServer".Trim()) { "$LoginServer".Trim() } else { "$("$Registry".Trim().ToLowerInvariant()).azurecr.io" }
    try {
        $r = Invoke-PimAcrData -LoginServer $ls -Repository $Repository -Path "/acr/v1/$Repository/_tags/$Tag"
        return "$($r.tag.digest)".Trim()
    } catch { $global:PimSetupRestLastError = "$($_.Exception.Message)"; return '' }
}

# ======================================================================================================================
# managed identity + Azure RBAC
# ======================================================================================================================

function Get-PimArmIdentity {
    <# az identity show -g RG -n N | --ids ID : .id, .properties.principalId, .properties.clientId (az flattens them). #>
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$Name, [string]$ResourceId, [switch]$ErrorAsNull)
    $id = if ("$ResourceId".Trim()) { "$ResourceId".Trim() } else { Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ManagedIdentity/userAssignedIdentities' $Name }
    Invoke-PimSetupArm -Path $id -ApiVersion (Get-PimSetupApiVersion msi) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmIdentity {
    <# az identity create -g RG -n N -l L (existing: returned untouched). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location, [hashtable]$Tags)
    $cur = Get-PimArmIdentity -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if ($cur) { return $cur }
    $body = @{ location = $Location }
    if ($Tags) { $body.tags = $Tags }
    Invoke-PimSetupArm -Method PUT -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.ManagedIdentity/userAssignedIdentities' $Name) -Body $body -ApiVersion (Get-PimSetupApiVersion msi)
}

function Get-PimArmIdentities {
    <# az identity list -g RG #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $r = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities" -ApiVersion (Get-PimSetupApiVersion msi) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

# Built-in role ids (the same in every tenant) -- no lookup needed for the roles setup grants.
$script:PimSetupBuiltInRoles = @{
    'owner'                                  = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    'contributor'                            = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
    'reader'                                 = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
    'user access administrator'              = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'
    'role based access control administrator' = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168'
    'acrpull'                                = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
    'acrpush'                                = '8311e382-0749-4cb8-b61a-304f252e45ec'
    'network contributor'                    = '4d97b98b-1d4f-4787-a291-c67834d212e7'
    'container apps jobs operator'           = 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b'
    'container apps contributor'             = '358470bc-b998-42bd-ab17-a7e34c199c0f'
    'storage blob data reader'               = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
    'storage blob data contributor'          = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
    'key vault secrets user'                 = '4633458b-17de-408a-b874-0445c86b69e6'
    'key vault secrets officer'              = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
    'key vault crypto user'                  = '12338af0-0e69-4776-bea7-57ae8d297424'
    'monitoring reader'                      = '43d0d8ad-25c7-4714-9337-8ba259a9fe05'
    'log analytics reader'                   = '73c42c96-874c-492b-b04d-ab87d138a893'
    'sql db contributor'                     = '9b7fa17d-e63e-47b0-bb0a-15c516ac86ec'
    'sql server contributor'                 = '6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437'
}

$global:PimSetupBuiltInRolesMap = $script:PimSetupBuiltInRoles
function Get-PimSetupBuiltInRoles { if ($script:PimSetupBuiltInRoles) { return $script:PimSetupBuiltInRoles }; if ($global:PimSetupBuiltInRolesMap) { return $global:PimSetupBuiltInRolesMap }; return @{} }

function Get-PimArmRoleDefinitionId {
    <#
      A role NAME (or a GUID, or a full roleDefinitions id) -> the full role definition id at -SubscriptionId.
      Built-in names resolve offline; any other name is looked up once (roleName filter) and cached.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Role, [string]$Scope)
    $r = "$Role".Trim()
    if ($r -match '(?i)/providers/Microsoft\.Authorization/roleDefinitions/[0-9a-f-]{36}$') { return $r }
    $guid = $null
    if ($r -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $guid = $r.ToLowerInvariant() }
    elseif ((Get-PimSetupBuiltInRoles).ContainsKey($r.ToLowerInvariant())) { $guid = (Get-PimSetupBuiltInRoles)[$r.ToLowerInvariant()] }
    else {
        if (-not $script:PimSetupRoleCache) { $script:PimSetupRoleCache = @{} }
        $key = "$SubscriptionId|$($r.ToLowerInvariant())"
        if (-not $script:PimSetupRoleCache.ContainsKey($key)) {
            $at = if ("$Scope".Trim()) { "$Scope".Trim() } else { "/subscriptions/$SubscriptionId" }
            $f = [uri]::EscapeDataString("roleName eq '$($r.Replace("'", "''"))'")
            $d = @(Invoke-PimSetupArm -Path "$at/providers/Microsoft.Authorization/roleDefinitions?`$filter=$f" -ApiVersion (Get-PimSetupApiVersion authorization) -All)
            $hit = @($d | Where-Object { $_ }) | Select-Object -First 1
            if (-not $hit) { throw "Azure role '$r' was not found at $at." }
            $script:PimSetupRoleCache[$key] = ("$($hit.name)").ToLowerInvariant()
        }
        $guid = $script:PimSetupRoleCache[$key]
    }
    return "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$guid"
}

function Get-PimArmRoleName {
    <# The display name of a role definition id (built-ins offline, others read once). '' when unreadable. #>
    param([Parameter(Mandatory)][string]$RoleDefinitionId)
    $g = (("$RoleDefinitionId" -split '/')[-1]).ToLowerInvariant()
    $builtIn = ''
    $bi = Get-PimSetupBuiltInRoles
    foreach ($k in @($bi.Keys)) { if ($bi[$k] -eq $g) { $builtIn = "$k" } }
    if ($builtIn) {
        # the canonical casing az prints
        $special = @{ 'acrpull' = 'AcrPull'; 'acrpush' = 'AcrPush'; 'sql db contributor' = 'SQL DB Contributor'; 'sql server contributor' = 'SQL Server Contributor' }
        if ($special.ContainsKey($builtIn)) { return $special[$builtIn] }
        return ((Get-Culture).TextInfo.ToTitleCase($builtIn))
    }
    if (-not $script:PimSetupRoleNames) { $script:PimSetupRoleNames = @{} }
    if (-not $script:PimSetupRoleNames.ContainsKey($g)) {
        $d = Invoke-PimSetupArm -Path "$RoleDefinitionId" -ApiVersion (Get-PimSetupApiVersion authorization) -ErrorAsNull
        $script:PimSetupRoleNames[$g] = "$($d.properties.roleName)"
    }
    return $script:PimSetupRoleNames[$g]
}

function Get-PimArmRoleAssignments {
    <#
      az role assignment list --assignee P --scope S [--role R] [--include-inherited] : the assignments of principal P
      AT scope S (az's default: exact scope; -IncludeInherited also returns the ones inherited from above). Each carries
      az's flattened fields too: .scope, .roleDefinitionId, .roleDefinitionName, .principalId.
    #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [string]$Role, [switch]$IncludeInherited, [string]$SubscriptionId)
    $sc = "$Scope".Trim().TrimEnd('/')
    $sub = if ("$SubscriptionId".Trim()) { "$SubscriptionId".Trim() } else { Get-PimArmIdPart -Id $sc -Segment 'subscriptions' }
    $f = [uri]::EscapeDataString("principalId eq '$("$PrincipalId".Trim())'")
    $all = @(Invoke-PimSetupArm -Path "$sc/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" -ApiVersion (Get-PimSetupApiVersion authorization) -All)
    $want = $null
    if ("$Role".Trim()) { $want = ((Get-PimArmRoleDefinitionId -SubscriptionId $sub -Role $Role) -split '/')[-1].ToLowerInvariant() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($all | Where-Object { $_ })) {
        $p = $a.properties
        if ("$($p.principalId)" -ine "$PrincipalId".Trim()) { continue }
        $aScope = "$($p.scope)".TrimEnd('/')
        if ($IncludeInherited) {
            if (-not ($sc.StartsWith($aScope, [StringComparison]::OrdinalIgnoreCase) -or $aScope -eq '')) { continue }
        } elseif ($aScope -ine $sc) { continue }
        $rid = "$($p.roleDefinitionId)"
        if ($want -and ($rid -split '/')[-1].ToLowerInvariant() -ne $want) { continue }
        $o = [ordered]@{ id = "$($a.id)"; name = "$($a.name)"; scope = $aScope; principalId = "$($p.principalId)"; principalType = "$($p.principalType)"
                         roleDefinitionId = $rid; roleDefinitionName = (Get-PimArmRoleName -RoleDefinitionId $rid); properties = $p }
        $out.Add([pscustomobject]$o)
    }
    return @($out.ToArray())
}

function New-PimArmRoleAssignment {
    <#
      az role assignment create --assignee-object-id P --assignee-principal-type T --role R --scope S
      PUT with a new assignment name. An assignment that already exists (409 RoleAssignmentExists) is success, as az
      treated it. A freshly created principal that ARM cannot see yet (PrincipalNotFound) is retried by Invoke-PimRest.
    #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$Role,
          [ValidateSet('ServicePrincipal', 'User', 'Group', 'ForeignGroup', 'Device')][string]$PrincipalType = 'ServicePrincipal', [string]$SubscriptionId)
    $sc = "$Scope".Trim().TrimEnd('/')
    $sub = if ("$SubscriptionId".Trim()) { "$SubscriptionId".Trim() } else { Get-PimArmIdPart -Id $sc -Segment 'subscriptions' }
    $rd = Get-PimArmRoleDefinitionId -SubscriptionId $sub -Role $Role -Scope $sc
    # Above a subscription (a management group, the tenant root) ARM takes the tenant-level definition id.
    if ($sc -notmatch '^(?i)/subscriptions/') { $rd = '/providers/Microsoft.Authorization/roleDefinitions/' + (($rd -split '/')[-1]) }
    $name = [guid]::NewGuid().ToString()
    $body = @{ properties = @{ roleDefinitionId = $rd; principalId = "$PrincipalId".Trim(); principalType = $PrincipalType } }
    try {
        return (Invoke-PimSetupArm -Method PUT -Path "$sc/providers/Microsoft.Authorization/roleAssignments/$name" -Body $body -ApiVersion (Get-PimSetupApiVersion authorization))
    } catch {
        if ("$($_.Exception.Message)" -match '(?i)RoleAssignmentExists|already exists') { return [pscustomobject]@{ existed = $true } }
        throw
    }
}

# ======================================================================================================================
# Azure SQL
# ======================================================================================================================

function Get-PimArmSqlServer {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Name) -ApiVersion (Get-PimSetupApiVersion sql) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimArmSqlServers {
    <# az sql server list --subscription S #>
    param([Parameter(Mandatory)][string]$SubscriptionId)
    $r = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Sql/servers" -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

function New-PimArmSqlServer {
    <#
      az sql server create -l L [--enable-ad-only-auth --external-admin-principal-type ... --external-admin-name ...
      --external-admin-sid ...] [--assign-identity --user-assigned-identity-id ... --primary-user-assigned-identity-id ...]
      -Properties is the server's properties object as ARM takes it; -Identity the identity block. Waits for the create.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][hashtable]$Properties, [hashtable]$Identity, [hashtable]$Tags)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Name
    $body = @{ location = $Location; properties = $Properties }
    if ($Identity) { $body.identity = $Identity }
    if ($Tags) { $body.tags = $Tags }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion sql))
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion sql) -TimeoutSeconds 1200
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "the SQL server '$Name' did not provision ($st)." }
    Get-PimArmSqlServer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Update-PimArmSqlServer {
    <# az sql server update (e.g. --enable-public-network): PATCH of the named properties. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Properties)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Name
    [void](Invoke-PimSetupArm -Method PATCH -Path $id -Body @{ properties = $Properties } -ApiVersion (Get-PimSetupApiVersion sql))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion sql))
    Get-PimArmSqlServer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmSqlAdmins {
    <# az sql server ad-admin list : @( { sid; login; tenantId; administratorType } ) (az's flattened fields). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'administrators') -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull
    return @(@($r | Where-Object { $_ }) | ForEach-Object {
        [pscustomobject]@{ sid = "$($_.properties.sid)"; login = "$($_.properties.login)"; tenantId = "$($_.properties.tenantId)"; administratorType = "$($_.properties.administratorType)"; id = "$($_.id)" } })
}

function Set-PimArmSqlAdmin {
    <# az sql server ad-admin create --display-name LOGIN --object-id SID : PUT administrators/ActiveDirectory. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server,
          [Parameter(Mandatory)][string]$Login, [Parameter(Mandatory)][string]$ObjectId, [string]$TenantId)
    $props = @{ administratorType = 'ActiveDirectory'; login = $Login; sid = $ObjectId }
    $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { "$($global:PIM_TenantId)".Trim() }
    if ($tid) { $props.tenantId = $tid }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'administrators/ActiveDirectory'
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ properties = $props } -ApiVersion (Get-PimSetupApiVersion sql))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion sql))
}

function Get-PimArmSqlDb {
    <# az sql db show : .properties.currentServiceObjectiveName / maxSizeBytes / status / autoPauseDelay / elasticPoolId; .tags. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "databases/$Name") -ApiVersion (Get-PimSetupApiVersion sql) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmSqlDb {
    <#
      az sql db create (-Create: PUT, location required) | az sql db update (PATCH). -Sku is @{ name; tier; family; capacity }
      as ARM takes it; -Properties the database properties (maxSizeBytes, autoPauseDelay, minCapacity, ...). Waits.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server,
          [Parameter(Mandatory)][string]$Name, [switch]$Create, [string]$Location, [hashtable]$Sku, [hashtable]$Properties, [hashtable]$Tags)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "databases/$Name"
    $body = @{}
    if ($Sku) { $body.sku = $Sku }
    if ($Properties) { $body.properties = $Properties }
    if ($Tags) { $body.tags = $Tags }
    if ($Create) {
        if (-not "$Location".Trim()) { $srv = Get-PimArmSqlServer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Server; $Location = "$($srv.location)" }
        $body.location = $Location
        [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion sql))
    } else {
        [void](Invoke-PimSetupArm -Method PATCH -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion sql))
    }
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion sql) -TimeoutSeconds 1200)
    Get-PimArmSqlDb -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Server $Server -Name $Name
}

function Get-PimArmSqlFirewallRule {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "firewallRules/$Name") -ApiVersion (Get-PimSetupApiVersion sql) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimArmSqlFirewallRules {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'firewallRules') -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

function Set-PimArmSqlFirewallRule {
    <# az sql server firewall-rule create -n N --start-ip-address A --end-ip-address B #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$StartIp, [Parameter(Mandatory)][string]$EndIp)
    Invoke-PimSetupArm -Method PUT -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "firewallRules/$Name") `
        -Body @{ properties = @{ startIpAddress = $StartIp; endIpAddress = $EndIp } } -ApiVersion (Get-PimSetupApiVersion sql)
}

function Remove-PimArmSqlFirewallRule {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Name)
    Invoke-PimSetupArm -Method DELETE -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "firewallRules/$Name") -ApiVersion (Get-PimSetupApiVersion sql) -NotFoundOk
}

function Get-PimArmSqlConnectionPolicy {
    <# az sql server conn-policy show --query connectionType -> 'Default' | 'Redirect' | 'Proxy' | '' #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server)
    $p = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'connectionPolicies/default') -ApiVersion (Get-PimSetupApiVersion sql) -ErrorAsNull
    if ($p) { return "$($p.properties.connectionType)" }
    return ''
}

function Set-PimArmSqlConnectionPolicy {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][ValidateSet('Default', 'Redirect', 'Proxy')][string]$ConnectionType)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'connectionPolicies/default'
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ properties = @{ connectionType = $ConnectionType } } -ApiVersion (Get-PimSetupApiVersion sql))
}

# ======================================================================================================================
# Container Apps: environment, app, job (read-modify-write; see PIM-ArmContainerApps.ps1 for the image rolls)
# ======================================================================================================================

function Get-PimArmAcaEnv {
    <# az containerapp env show -g RG -n N | --ids ID #>
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$Name, [string]$ResourceId, [switch]$ErrorAsNull)
    $id = if ("$ResourceId".Trim()) { "$ResourceId".Trim() } else { Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $Name }
    Invoke-PimSetupArm -Path $id -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmAcaEnv {
    <#
      az containerapp env create (-Create: PUT location + properties) | az containerapp env update (PATCH properties).
      Waits for provisioning (an environment takes minutes) and returns the environment as it reads back.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][hashtable]$Properties, [switch]$Create, [string]$Location, [hashtable]$Tags, [int]$TimeoutSeconds = 1800)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $Name
    $body = @{ properties = $Properties }
    if ($Tags) { $body.tags = $Tags }
    if ($Create) {
        if (-not "$Location".Trim()) { throw 'Set-PimArmAcaEnv -Create needs -Location.' }
        $body.location = $Location
        [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion aca))
    } else {
        [void](Invoke-PimSetupArm -Method PATCH -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion aca))
    }
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds $TimeoutSeconds
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "the Container Apps environment '$Name' did not provision ($st)." }
    Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Get-PimArmAcaApp {
    <# az containerapp show -g RG -n N : the app or $null (az's '' on a missing app). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name) -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimArmAcaAppNames {
    <# az containerapp list -g RG --query "[].name" #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $r = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps" -ApiVersion (Get-PimSetupApiVersion aca) -All -ErrorAsNull
    return @(@($r | Where-Object { $_ }) | ForEach-Object { "$($_.name)".Trim() } | Where-Object { $_ })
}

function Set-PimArmAcaApp {
    <#
      az containerapp create --yaml (-Create: PUT the whole resource) | az containerapp update --yaml (PATCH).
      -Resource is the ARM resource as a hashtable: @{ location; identity; properties = @{ managedEnvironmentId;
      configuration; template } }. Waits for provisioning; returns the app as it reads back.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][object]$Resource, [switch]$Create, [int]$TimeoutSeconds = 900)   # a hashtable, or a captured resource object (Rebuild)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name
    $m = if ($Create) { 'PUT' } else { 'PATCH' }
    [void](Invoke-PimSetupArm -Method $m -Path $id -Body $Resource -ApiVersion (Get-PimSetupApiVersion aca))
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds $TimeoutSeconds
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "container app '$Name' did not provision ($st)." }
    Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Set-PimArmAcaAppEnvVars {
    <#
      az containerapp update --set-env-vars K=V ... : read-modify-write of the container's env (the other variables,
      secret refs, probes and resources stay), one PATCH of the whole template. -ContainerName as Set-PimAcaAppImage.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][hashtable]$Env, [string]$ContainerName, [string]$Image)
    $app = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $app) { throw "container app '$Name' not found in $ResourceGroup." }
    $cs = @($app.properties.template.containers)
    $t = if ("$ContainerName".Trim()) { @($cs | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1 } elseif ($cs.Count -eq 1) { $cs[0] } else { $null }
    if (-not $t) { throw "container app '$Name': cannot tell which of $($cs.Count) containers to change -- pass -ContainerName." }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($t.env)) { if ($e -and -not $Env.ContainsKey("$($e.name)")) { $list.Add($e) } }
    foreach ($k in $Env.Keys) { $list.Add([pscustomobject]@{ name = "$k"; value = "$($Env[$k])" }) }
    $t | Add-Member -NotePropertyName env -NotePropertyValue @($list.ToArray()) -Force
    if ("$Image".Trim()) { $t.image = "$Image".Trim() }
    Set-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Resource @{ properties = @{ template = $app.properties.template } }
}

function Set-PimArmAcaAppConfiguration {
    <#
      Read-modify-write of ONE part of properties.configuration (ingress, registries, secrets, activeRevisionsMode ...):
      -Mutate receives the current configuration object and changes it in place; the whole configuration is written back
      (configuration.secrets come back WITHOUT values from a GET, so they are re-read with listSecrets first and kept).
      az containerapp ingress update / registry set / secret set / ingress access-restriction set.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][scriptblock]$Mutate)
    $app = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $app) { throw "container app '$Name' not found in $ResourceGroup." }
    $cfg = $app.properties.configuration
    if (-not $cfg) { $cfg = [pscustomobject]@{} }
    # Throws when the secrets cannot be listed -- never write a configuration that would drop them.
    $secrets = @(Get-PimArmAcaAppSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name)
    if ($secrets.Count -lt @($cfg.secrets | Where-Object { $_ }).Count) { throw "container app '$Name': listSecrets returned $($secrets.Count) secret(s) but the app declares $(@($cfg.secrets).Count) -- refusing to write a configuration that would drop secrets." }
    $cfg | Add-Member -NotePropertyName secrets -NotePropertyValue @($secrets | ForEach-Object { $s = [ordered]@{ name = "$($_.name)" }; if ("$($_.keyVaultUrl)".Trim()) { $s.keyVaultUrl = "$($_.keyVaultUrl)"; $s.identity = "$($_.identity)" } else { $s.value = "$($_.value)" }; [pscustomobject]$s }) -Force
    & $Mutate $cfg
    Set-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Resource @{ properties = @{ configuration = $cfg } }
}

function Get-PimArmAcaAppSecrets {
    <#
      az containerapp secret list --show-values : @( { name; value; keyVaultUrl; identity } ).
      🔴 THROWS when the list cannot be read (unless -ErrorAsNull): Set-PimArmAcaAppConfiguration writes the configuration
      back WITH these values, and an unread list written back as "no secrets" would DELETE every secret on the app.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    $r = Invoke-PimSetupArm -Method POST -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name 'listSecrets') -ApiVersion (Get-PimSetupApiVersion aca) -Body @{} -ErrorAsNull:$ErrorAsNull   # a body-less POST is refused with 415 (2026-10-10)
    return @(@($r.value) | Where-Object { $_ })
}

function Set-PimArmAcaAppSecret {
    <# az containerapp secret set --secrets NAME=VALUE : every other secret is kept (with its value). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$SecretName, [Parameter(Mandatory)][string]$Value)
    Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Mutate {
        param($cfg)
        $keep = @(@($cfg.secrets) | Where-Object { $_ -and "$($_.name)" -ne $SecretName })
        # $SecretName / $Value resolve dynamically from this function's scope (the block runs inside the call below);
        # no bound closure -- engine code must not bind one that cannot see dot-sourced functions (Test-PimHybridWorker L19).
        $cfg.secrets = @($keep) + @([pscustomobject]@{ name = $SecretName; value = $Value })
    }
}

function Get-PimArmAcaRevisions {
    <# az containerapp revision list -g RG -n APP : every revision (.name, .properties.active, .properties.createdTime, ...). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name 'revisions') -ApiVersion (Get-PimSetupApiVersion aca) -All -ErrorAsNull:$ErrorAsNull
    return @($r | Where-Object { $_ })
}

function Get-PimArmAcaRevision {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Revision, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name "revisions/$Revision") -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Invoke-PimArmAcaRevisionAction {
    <# az containerapp revision activate | deactivate | restart --revision R #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Revision, [Parameter(Mandatory)][ValidateSet('activate', 'deactivate', 'restart')][string]$Action)
    Invoke-PimSetupArm -Method POST -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name "revisions/$Revision/$Action") -Body @{} -ApiVersion (Get-PimSetupApiVersion aca)
}

function Get-PimArmAcaReplicas {
    <# az containerapp replica list --revision R : the replica names. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Revision)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name "revisions/$Revision/replicas") -ApiVersion (Get-PimSetupApiVersion aca) -ErrorAsNull
    return @(@($r.value) | Where-Object { $_ } | ForEach-Object { "$($_.name)".Trim() } | Where-Object { $_ })
}

function Get-PimArmAcaAuthConfig {
    <# az containerapp auth show : the authConfigs/current resource (.properties.platform / identityProviders / globalValidation ...), $null when none. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name 'authConfigs/current') -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmAcaAuthConfig {
    <#
      az containerapp auth update / auth microsoft update : READ-MODIFY-WRITE of authConfigs/current. -Mutate receives the
      current properties (a fresh object when none exists) and changes it in place; the whole document is PUT back.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Mutate)
    $cur = Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    $props = if ($cur -and $cur.properties) { $cur.properties } else { [pscustomobject]@{} }
    & $Mutate $props
    Invoke-PimSetupArm -Method PUT -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $Name 'authConfigs/current') -Body @{ properties = $props } -ApiVersion (Get-PimSetupApiVersion aca)
}

function Get-PimArmAcaJob {
    <# az containerapp job show -g RG -n N : the job or $null. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name) -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimArmAcaJobList {
    <# az containerapp job list -g RG : every job object (@() when the list cannot be read and -ErrorAsNull). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [switch]$ErrorAsNull)
    $r = Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs" -ApiVersion (Get-PimSetupApiVersion aca) -All -ErrorAsNull:$ErrorAsNull
    return @($r | Where-Object { $_ })
}

function Set-PimArmAcaJob {
    <#
      az containerapp job create --yaml (-Create: PUT the whole resource) | az containerapp job update --yaml (PATCH).
      -Resource: @{ location; identity; properties = @{ environmentId; configuration; template } }. Waits; returns it.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][object]$Resource, [switch]$Create, [int]$TimeoutSeconds = 900)   # a hashtable, or a captured resource object (Rebuild)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name
    $m = if ($Create) { 'PUT' } else { 'PATCH' }
    [void](Invoke-PimSetupArm -Method $m -Path $id -Body $Resource -ApiVersion (Get-PimSetupApiVersion aca))
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds $TimeoutSeconds
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "container apps job '$Name' did not provision ($st)." }
    Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
}

function Set-PimArmAcaJobIdentity {
    <#
      az containerapp job identity assign [--system-assigned] [--user-assigned ID ...] : the identity block is MERGED
      (identities already attached stay), one PATCH.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [switch]$SystemAssigned, [string[]]$UserAssigned = @())
    $job = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $job) { throw "container apps job '$Name' not found in $ResourceGroup." }
    $curType = "$($job.identity.type)"
    $sys = $SystemAssigned -or ($curType -match '(?i)SystemAssigned')
    $ua = [ordered]@{}
    if ($job.identity -and $job.identity.userAssignedIdentities) { foreach ($p in $job.identity.userAssignedIdentities.PSObject.Properties) { $ua[$p.Name] = @{} } }
    foreach ($u in @($UserAssigned | Where-Object { "$_".Trim() })) { $ua["$u".Trim()] = @{} }
    $type = if ($sys -and $ua.Count) { 'SystemAssigned,UserAssigned' } elseif ($sys) { 'SystemAssigned' } elseif ($ua.Count) { 'UserAssigned' } else { 'None' }
    $ident = @{ type = $type }
    if ($ua.Count) { $ident.userAssignedIdentities = $ua }
    Set-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Resource @{ identity = $ident }
}

function Start-PimArmAcaJob {
    <# az containerapp job start --query name : the execution name ('' when it could not start; reason in $global:PimSetupRestLastError). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $r = Invoke-PimSetupArm -Method POST -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name 'start') -Body @{} -ApiVersion (Get-PimSetupApiVersion aca) -ErrorAsNull
    if ($r -and $r.PSObject.Properties['name']) { return "$($r.name)" }
    return ''
}

function Get-PimArmAcaJobExecution {
    <# az containerapp job execution show --job-execution-name E : .properties.status ('Running', 'Succeeded', 'Failed', ...). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Execution)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name "executions/$Execution") -ApiVersion (Get-PimSetupApiVersion aca) -ErrorAsNull
}

function Get-PimArmAcaJobExecutions {
    <# az containerapp job execution list : every execution, newest first as ARM returns them. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name 'executions') -ApiVersion (Get-PimSetupApiVersion aca) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

function Get-PimArmAcaJobLogs {
    <#
      az containerapp job logs show --execution E --tail N : the console lines of one execution, from the environment's
      Log Analytics workspace (ContainerAppConsoleLogs_CL). Diagnostics only: @() when nothing can be read (the logs reach
      the workspace a few minutes after the execution; az's live stream had the same gap for a finished execution).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Execution, [int]$Tail = 100, [string]$EnvironmentName)
    $job = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -ErrorAsNull
    $envId = if ($job) { "$($job.properties.environmentId)" } else { '' }
    if (-not $envId -and "$EnvironmentName".Trim()) { $envId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $EnvironmentName }
    if (-not $envId) { return @() }
    $env = Get-PimArmAcaEnv -ResourceId $envId -ErrorAsNull
    $cid = "$($env.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim()
    if (-not $cid) { return @() }
    $ex = "$Execution".Replace("'", "''")
    $q = "ContainerAppConsoleLogs_CL | where ContainerGroupName_s startswith '$ex' | sort by TimeGenerated asc | take $([Math]::Max(1, $Tail)) | project TimeGenerated, Log_s"
    return @(Invoke-PimLogAnalyticsQuery -WorkspaceCustomerId $cid -Query $q | ForEach-Object { "$($_.Log_s)" })
}

# ======================================================================================================================
# Microsoft Graph: applications, service principals, users, groups, consent
# ======================================================================================================================

function Test-PimSetupGuid { param([string]$Value) return ("$Value".Trim() -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') }

function Get-PimGraphServicePrincipal {
    <#
      az ad sp show --id X : X is an appId OR an object id (az tries both). $null when neither exists.
    #>
    param([Parameter(Mandatory)][string]$Id, [string]$Select, [switch]$ErrorAsNull)
    $q = if ("$Select".Trim()) { "?`$select=$Select" } else { '' }
    $x = "$Id".Trim()
    $sp = Invoke-PimSetupGraph -Path "/servicePrincipals(appId='$x')$q" -NotFoundOk -ErrorAsNull:$ErrorAsNull
    if (-not $sp -and (Test-PimSetupGuid $x)) { $sp = Invoke-PimSetupGraph -Path "/servicePrincipals/$x$q" -NotFoundOk -ErrorAsNull:$ErrorAsNull }
    return $sp
}

function New-PimGraphServicePrincipal {
    <# az ad sp create --id APPID #>
    param([Parameter(Mandatory)][string]$AppId)
    Invoke-PimSetupGraph -Method POST -Path '/servicePrincipals' -Body @{ appId = "$AppId".Trim() }
}

function Update-PimGraphServicePrincipal {
    <# az ad sp update --id OBJECTID --set k=v : PATCH. #>
    param([Parameter(Mandatory)][string]$ObjectId, [Parameter(Mandatory)][hashtable]$Properties)
    Invoke-PimSetupGraph -Method PATCH -Path "/servicePrincipals/$("$ObjectId".Trim())" -Body $Properties
}

function Get-PimGraphApplication {
    <# az ad app show --id X : X is an appId OR an object id. $null when neither exists. #>
    param([Parameter(Mandatory)][string]$Id, [switch]$ErrorAsNull)
    $x = "$Id".Trim()
    $a = Invoke-PimSetupGraph -Path "/applications(appId='$x')" -NotFoundOk -ErrorAsNull:$ErrorAsNull
    if (-not $a -and (Test-PimSetupGuid $x)) { $a = Invoke-PimSetupGraph -Path "/applications/$x" -NotFoundOk -ErrorAsNull:$ErrorAsNull }
    return $a
}

function Find-PimGraphApplications {
    <# az ad app list --identifier-uri U | --display-name N : the matching applications. #>
    param([string]$IdentifierUri, [string]$DisplayName)
    $f = if ("$IdentifierUri".Trim()) { "identifierUris/any(x:x eq '$("$IdentifierUri".Trim().Replace("'", "''"))')" }
         elseif ("$DisplayName".Trim()) { "displayName eq '$("$DisplayName".Trim().Replace("'", "''"))'" }
         else { throw 'Find-PimGraphApplications: pass -IdentifierUri or -DisplayName.' }
    $r = Invoke-PimSetupGraph -Path "/applications?`$filter=$([uri]::EscapeDataString($f))" -All
    return @($r | Where-Object { $_ })
}

function New-PimGraphApplication {
    <# az ad app create : POST /applications with the body as Graph takes it (displayName, signInAudience, web, ...). #>
    param([Parameter(Mandatory)][hashtable]$Body)
    Invoke-PimSetupGraph -Method POST -Path '/applications' -Body $Body
}

function Update-PimGraphApplication {
    <# az ad app update --id X ... : PATCH by object id (the appId is resolved first when given). #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][hashtable]$Properties)
    $app = Get-PimGraphApplication -Id $Id
    if (-not $app) { throw "application '$Id' not found." }
    [void](Invoke-PimSetupGraph -Method PATCH -Path "/applications/$($app.id)" -Body $Properties)
}

function Add-PimGraphAppPassword {
    <# az ad app credential reset --id X --append --years N [--display-name D] : the new secretText (never printed). #>
    param([Parameter(Mandatory)][string]$Id, [int]$Years = 1, [string]$DisplayName)
    $app = Get-PimGraphApplication -Id $Id
    if (-not $app) { throw "application '$Id' not found." }
    $pc = @{ endDateTime = (Get-Date).ToUniversalTime().AddYears([Math]::Max(1, $Years)).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ("$DisplayName".Trim()) { $pc.displayName = "$DisplayName".Trim() }
    $r = Invoke-PimSetupGraph -Method POST -Path "/applications/$($app.id)/addPassword" -Body @{ passwordCredential = $pc }
    return "$($r.secretText)"
}

function Get-PimGraphUser {
    <# az ad user show --id UPN|OID : $null when not found. #>
    param([Parameter(Mandatory)][string]$Id, [switch]$ErrorAsNull)
    Invoke-PimSetupGraph -Path "/users/$([uri]::EscapeDataString("$Id".Trim()))" -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Get-PimGraphGroup {
    <# az ad group show --group NAME|OID : by object id, else by display name (exactly one). $null when not found. #>
    param([Parameter(Mandatory)][string]$Id, [switch]$ErrorAsNull)
    $x = "$Id".Trim()
    if (Test-PimSetupGuid $x) { return (Invoke-PimSetupGraph -Path "/groups/$x" -NotFoundOk -ErrorAsNull:$ErrorAsNull) }
    $r = @(Invoke-PimSetupGraph -Path "/groups?`$filter=$([uri]::EscapeDataString("displayName eq '$($x.Replace("'", "''"))'"))" -All -ErrorAsNull:$ErrorAsNull)
    $hits = @($r | Where-Object { $_ })
    if ($hits.Count -eq 1) { return $hits[0] }
    return $null
}

function Find-PimGraphGroups {
    <# az ad group list --filter F #>
    param([Parameter(Mandatory)][string]$Filter)
    $r = Invoke-PimSetupGraph -Path "/groups?`$filter=$([uri]::EscapeDataString($Filter))" -All
    return @($r | Where-Object { $_ })
}

function Grant-PimGraphAdminConsent {
    <#
      az ad app permission admin-consent --id APPID : consent, for the whole tenant, to every permission the app's
      requiredResourceAccess lists -- delegated scopes as ONE AllPrincipals oauth2PermissionGrant per resource (created,
      or its scope string widened), application roles as appRoleAssignments. Returns @{ grantedScopes; grantedRoles }.
    #>
    param([Parameter(Mandatory)][string]$AppId)
    $app = Get-PimGraphApplication -Id $AppId
    if (-not $app) { throw "application '$AppId' not found." }
    $client = Get-PimGraphServicePrincipal -Id "$($app.appId)"
    if (-not $client) { throw "application '$AppId' has no service principal in this tenant (az ad sp create --id first)." }
    $scopes = 0; $roles = 0
    foreach ($rra in @($app.requiredResourceAccess | Where-Object { $_ })) {
        $res = Get-PimGraphServicePrincipal -Id "$($rra.resourceAppId)"
        if (-not $res) { throw "the API $($rra.resourceAppId) has no service principal in this tenant." }
        $want = @(); $wantRoles = @()
        foreach ($ra in @($rra.resourceAccess | Where-Object { $_ })) {
            if ("$($ra.type)" -eq 'Scope') { $v = @($res.oauth2PermissionScopes | Where-Object { "$($_.id)" -eq "$($ra.id)" } | ForEach-Object { "$($_.value)" }) | Select-Object -First 1; if ($v) { $want += $v } }
            elseif ("$($ra.type)" -eq 'Role') { $wantRoles += "$($ra.id)" }
        }
        if ($want.Count) {
            $f = [uri]::EscapeDataString("clientId eq '$($client.id)' and resourceId eq '$($res.id)' and consentType eq 'AllPrincipals'")
            $g = @(Invoke-PimSetupGraph -Path "/oauth2PermissionGrants?`$filter=$f" -All) | Where-Object { $_ } | Select-Object -First 1
            if ($g) {
                $have = @("$($g.scope)" -split '\s+' | Where-Object { $_ })
                $merged = @($have + $want | Select-Object -Unique)
                if ($merged.Count -ne $have.Count) { [void](Invoke-PimSetupGraph -Method PATCH -Path "/oauth2PermissionGrants/$($g.id)" -Body @{ scope = ($merged -join ' ') }) }
            } else {
                [void](Invoke-PimSetupGraph -Method POST -Path '/oauth2PermissionGrants' -Body @{ clientId = "$($client.id)"; consentType = 'AllPrincipals'; resourceId = "$($res.id)"; scope = (@($want | Select-Object -Unique) -join ' ') })
            }
            $scopes += $want.Count
        }
        if ($wantRoles.Count) {
            $assigned = @(Invoke-PimSetupGraph -Path "/servicePrincipals/$($client.id)/appRoleAssignments" -All | Where-Object { $_ -and "$($_.resourceId)" -eq "$($res.id)" } | ForEach-Object { "$($_.appRoleId)" })
            foreach ($rid in $wantRoles) {
                if ($assigned -contains $rid) { continue }
                [void](Invoke-PimSetupGraph -Method POST -Path "/servicePrincipals/$($client.id)/appRoleAssignments" -Body @{ principalId = "$($client.id)"; resourceId = "$($res.id)"; appRoleId = $rid })
                $roles++
            }
        }
    }
    return @{ grantedScopes = $scopes; grantedRoles = $roles }
}

function Get-PimSetupSignedInObjectId {
    <#
      The object id of WHO the setup calls run as (az ad signed-in-user show / az ad sp show --id <account>): the `oid`
      claim of the ARM token PIM-Rest issues. '' when no token can be had. Never prints the token.
    #>
    try {
        $t = if ($global:PIM_SetupRestStub) { "$($global:PIM_SetupTokenStub)" } else { Get-PimRestToken -Resource 'arm' }
        $seg = "$t".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json
        return "$($c.oid)".Trim().ToLowerInvariant()
    } catch { return '' }
}

function Write-PimGraphTokenRolesHint {
    <#
      "Insufficient privileges" right after a grant: say what the Graph token PIM-Rest presents actually carries (the
      _PimAz.ps1 hint, read from PIM-Rest's token instead of az's cache). Said once per run.
    #>
    if ($script:PimSetupPrivHintSaid) { return }
    $script:PimSetupPrivHintSaid = $true
    try {
        $t = Get-PimRestToken -Resource 'graph'
        $seg = "$t".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
        $roles = @(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json).roles | Where-Object { "$_".Trim() })
    } catch { return }
    if ($roles.Count) {
        Write-Host ("      the Graph token carries: {0}" -f ((@($roles) | Sort-Object) -join ', ')) -ForegroundColor Yellow
        Write-Host  '      -- so this operation needs one that is NOT in that list. Grant it and re-run.' -ForegroundColor Yellow
    } else {
        Write-Host  '      THE GRAPH TOKEN CARRIES NO APPLICATION PERMISSIONS AT ALL (empty roles claim).' -ForegroundColor Red
        Write-Host  '      If the permissions WERE granted minutes ago, the token predates the grant: re-run in a new PowerShell window.' -ForegroundColor Yellow
    }
}

# ---- added for Invoke-PimDeployAll.ps1 ----

function Get-PimSetupAccount {
    <#
      az account show --subscription S : WHO the setup calls run as, in az's shape -- @{ id = <subscription>; tenantId;
      user = @{ type = 'user' | 'servicePrincipal'; name = <upn> | <appId> } } -- read from the claims of the ARM token
      PIM-Rest presents (a person's token carries a upn; an application's carries only its appid). $null when no token can
      be had. Never prints or returns the token. Test seam: $global:PIM_SetupTokenStub (used when PIM_SetupRestStub is set).
    #>
    param([string]$SubscriptionId, [string]$TenantId)
    try {
        $t = if ($global:PIM_SetupRestStub) { "$($global:PIM_SetupTokenStub)" }
             elseif ("$TenantId".Trim()) { Get-PimRestToken -Resource 'arm' -TenantId "$TenantId".Trim() }
             else { Get-PimRestToken -Resource 'arm' }
        $seg = "$t".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json
        $upn = "$(if ($c.upn) { $c.upn } elseif ($c.unique_name) { $c.unique_name } elseif ($c.preferred_username) { $c.preferred_username } else { '' })".Trim()
        $isUser = [bool]$upn -and ("$($c.idtyp)".Trim().ToLowerInvariant() -ne 'app')
        $name = if ($isUser) { $upn } else { "$(if ($c.appid) { $c.appid } else { $c.azp })".Trim() }
        if (-not $name) { return $null }
        return [pscustomobject]@{ id = "$SubscriptionId".Trim(); tenantId = "$($c.tid)".Trim().ToLowerInvariant()
                                  user = [pscustomobject]@{ type = $(if ($isUser) { 'user' } else { 'servicePrincipal' }); name = $name } }
    } catch { return $null }
}

# ---- added for Deploy-PimDownlinkJob.ps1 ----

function Get-PimArmAcaJobSecretNames {
    <# az containerapp job secret list --query "[].name" : the secret NAMES the job declares (a GET carries no values). Throws when unreadable. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $job = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name) -ApiVersion (Get-PimSetupApiVersion aca)
    if (-not $job) { throw "container apps job '$Name' not found in $ResourceGroup." }
    return @(@($job.properties.configuration.secrets) | Where-Object { $_ -and "$($_.name)".Trim() } | ForEach-Object { "$($_.name)".Trim() })
}

function Get-PimArmAcaJobSecrets {
    <#
      az containerapp job secret list --show-values : @( { name; value; keyVaultUrl; identity } ) via POST .../listSecrets.
      🔴 THROWS when the list cannot be read: a configuration written back from an unread list would DELETE the secrets.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name)
    $r = Invoke-PimSetupArm -Method POST -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name 'listSecrets') -ApiVersion (Get-PimSetupApiVersion aca) -Body @{}
    return @(@($r.value) | Where-Object { $_ })
}

function Remove-PimArmAcaJobSecret {
    <#
      az containerapp job secret remove --secret-names S --yes : READ-MODIFY-WRITE of the job's configuration -- every OTHER
      secret is written back WITH its value (from listSecrets), registries / trigger / timeouts kept, one PATCH, waited on.
      Refuses (throws) when the values cannot be read or do not cover every declared secret: writing the configuration back
      from an incomplete list would delete secrets that were meant to stay.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$SecretName)
    $path = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $Name
    $job = Invoke-PimSetupArm -Path $path -ApiVersion (Get-PimSetupApiVersion aca)
    if (-not $job) { throw "container apps job '$Name' not found in $ResourceGroup." }
    $cfg = $job.properties.configuration
    $declared = @(@($cfg.secrets) | Where-Object { $_ -and "$($_.name)".Trim() })
    $values = @(Get-PimArmAcaJobSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name)
    if ($values.Count -lt $declared.Count) { throw "job '$Name': listSecrets returned $($values.Count) secret(s) but the job declares $($declared.Count) -- refusing to write a configuration that would drop secrets." }
    $keep = @(foreach ($s in $values) {
        if ("$($s.name)" -eq $SecretName) { continue }
        $o = [ordered]@{ name = "$($s.name)" }
        if ("$($s.keyVaultUrl)".Trim()) { $o.keyVaultUrl = "$($s.keyVaultUrl)"; $o.identity = "$($s.identity)" } else { $o.value = "$($s.value)" }
        [pscustomobject]$o
    })
    $cfg | Add-Member -NotePropertyName secrets -NotePropertyValue @($keep) -Force
    [void](Invoke-PimSetupArm -Method PATCH -Path $path -Body @{ properties = @{ configuration = $cfg } } -ApiVersion (Get-PimSetupApiVersion aca))
    $st = Wait-PimArmProvisioned -Path $path -ApiVersion (Get-PimSetupApiVersion aca)
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "job '$Name' did not provision after removing secret '$SecretName' ($st)." }
}

# ======================================================================================================================
# ---- added for batch 2 (REQUIREMENTS 100.41): storage, private DNS links, SQL VNet rules, Key Vault, ACA host names,
#      deletes, app certificates
# ======================================================================================================================

function Get-PimArmResource {
    <# A GET of any ARM id (az ... show --ids ID): -Kind names the pinned api-version ('network', 'aca', ...). $null on 404. #>
    param([Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][string]$Kind, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path "$ResourceId".Trim() -ApiVersion (Get-PimSetupApiVersion $Kind) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Remove-PimArmResource {
    <# az ... delete --yes : DELETE by id (a missing resource is success), then wait until it reads back 404 (-Wait). #>
    param([Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][string]$Kind, [switch]$Wait, [int]$TimeoutSeconds = 900)
    $v = Get-PimSetupApiVersion $Kind
    [void](Invoke-PimSetupArm -Method DELETE -Path "$ResourceId".Trim() -ApiVersion $v -NotFoundOk)
    if (-not $Wait) { return }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Invoke-PimSetupArm -Path "$ResourceId".Trim() -ApiVersion $v -NotFoundOk -ErrorAsNull)) { return }
        Start-Sleep -Seconds 10
    }
}

function Get-PimArmSubscriptions {
    <# az account list --query "[].id" : every subscription id the signed-in identity can see. #>
    $r = Invoke-PimSetupArm -Path '/subscriptions' -ApiVersion (Get-PimSetupApiVersion subscriptions) -All -ErrorAsNull
    return @(@($r | Where-Object { $_ }) | ForEach-Object { "$($_.subscriptionId)".Trim() } | Where-Object { $_ })
}

function Get-PimArmLogAnalyticsList {
    <# az monitor log-analytics workspace list [-g RG] : every workspace (.name, .properties.customerId). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup)
    $scope = if ("$ResourceGroup".Trim()) { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" } else { "/subscriptions/$SubscriptionId" }
    $r = Invoke-PimSetupArm -Path "$scope/providers/Microsoft.OperationalInsights/workspaces" -ApiVersion (Get-PimSetupApiVersion logAnalytics) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

# ---- storage (control plane + the blob data plane) ----

function Get-PimArmStorageAccount {
    <# az storage account show : .id, .location, .properties.publicNetworkAccess / allowBlobPublicAccess / networkAcls. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $Name) -ApiVersion (Get-PimSetupApiVersion storage) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function New-PimArmStorageAccount {
    <#
      az storage account create --sku S --kind K --allow-blob-public-access B : PUT, then wait until it reads back Succeeded
      (the create answers 202 and the account is not readable at once -- a 404 while it is created is waited through).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [string]$Sku = 'Standard_LRS', [string]$Kind = 'StorageV2', [bool]$AllowBlobPublicAccess = $false,
          [int]$TimeoutSeconds = 600)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $Name
    $body = @{ location = $Location; sku = @{ name = $Sku }; kind = $Kind
               properties = @{ allowBlobPublicAccess = $AllowBlobPublicAccess; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $true } }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion (Get-PimSetupApiVersion storage))
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $sa = Get-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -ErrorAsNull
        $st = "$($sa.properties.provisioningState)"
        if ($sa -and $st -match '(?i)^Succeeded$') { return $sa }
        if ($sa -and $st -match '(?i)^(Failed|Canceled)$') { throw "the storage account '$Name' did not provision ($st)." }
        if ((Get-Date) -ge $deadline) { throw "the storage account '$Name' did not provision within $TimeoutSeconds s (state '$st')." }
        Start-Sleep -Seconds 5
    }
}

function Update-PimArmStorageAccount {
    <# az storage account update --public-network-access X | --allow-blob-public-access B : PATCH of the named properties only. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Properties)
    Invoke-PimSetupArm -Method PATCH -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $Name) -Body @{ properties = $Properties } -ApiVersion (Get-PimSetupApiVersion storage)
}

function Get-PimArmBlobContainer {
    <# az storage container-rm show : .properties.publicAccess ('None' | 'Blob' | 'Container'), $null when absent. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $Account "blobServices/default/containers/$Name") -ApiVersion (Get-PimSetupApiVersion storage) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmBlobContainer {
    <#
      az storage container-rm create (-Create: PUT) | az storage container-rm update --public-access X (PATCH). CONTROL plane:
      no data role and no allowed network needed, so a re-run behind a Deny firewall still works.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Name,
          [switch]$Create, [ValidateSet('', 'None', 'Blob', 'Container')][string]$PublicAccess = '')
    $props = @{}
    if ($PublicAccess) { $props.publicAccess = $PublicAccess }
    Invoke-PimSetupArm -Method $(if ($Create) { 'PUT' } else { 'PATCH' }) -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $Account "blobServices/default/containers/$Name") -Body @{ properties = $props } -ApiVersion (Get-PimSetupApiVersion storage)
}

function Invoke-PimBlobData {
    <#
      az storage blob upload | download | delete --auth-mode login : ONE blob call on the data plane with an Entra token
      (audience https://storage.azure.com) -- never an account key, never a SAS. PUT writes -Content as a block blob.
      Throws "<METHOD> <url> -> HTTP <code> : ..." like every other wrapper (a data-plane RBAC gap is HTTP 403).
    #>
    param([Parameter(Mandatory)][ValidateSet('PUT', 'GET', 'DELETE')][string]$Method, [Parameter(Mandatory)][string]$Account,
          [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob, [string]$Content)
    $h = @{ 'x-ms-version' = (Get-PimSetupApiVersion storageData) }
    if ($Method -eq 'PUT') { $h['x-ms-blob-type'] = 'BlockBlob' }
    $url = "https://$Account.blob.core.windows.net/$Container/$Blob"
    Invoke-PimSetupRest -Method $Method -Url $url -Body $(if ($Method -eq 'PUT') { "$Content" } else { $null }) -Resource 'https://storage.azure.com' -Headers $h
}

# ---- network: NIC, private DNS links (resolution policy), zone groups ----

function Get-PimArmPrivateDnsLink {
    <# az network private-dns link vnet show -z Z -n N : .id, .properties.resolutionPolicy, .properties.virtualNetwork.id. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName, [Parameter(Mandatory)][string]$Name, [switch]$ErrorAsNull)
    Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "virtualNetworkLinks/$Name") -ApiVersion (Get-PimSetupApiVersion privateDnsLink) -NotFoundOk -ErrorAsNull:$ErrorAsNull
}

function Set-PimArmPrivateDnsLink {
    <#
      az network private-dns link vnet create|update --virtual-network ID --registration-enabled false [--resolution-policy P]
      PUT of the whole link (idempotent), waited on. -ResolutionPolicy 'NxDomainRedirect': a name this zone has no record for
      still resolves publicly instead of failing.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$ZoneName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$VnetId, [bool]$RegistrationEnabled = $false, [string]$ResolutionPolicy)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $ZoneName "virtualNetworkLinks/$Name"
    $props = @{ virtualNetwork = @{ id = $VnetId }; registrationEnabled = $RegistrationEnabled }
    if ("$ResolutionPolicy".Trim()) { $props.resolutionPolicy = "$ResolutionPolicy".Trim() }
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = 'global'; properties = $props } -ApiVersion (Get-PimSetupApiVersion privateDnsLink))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion privateDnsLink))
}

function Get-PimArmPrivateDnsZoneGroups {
    <# az network private-endpoint dns-zone-group list --endpoint-name E #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$EndpointName)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateEndpoints' $EndpointName 'privateDnsZoneGroups') -ApiVersion (Get-PimSetupApiVersion network) -All -NotFoundOk -ErrorAsNull
    return @($r | Where-Object { $_ })
}

# ---- Azure SQL: virtual network rules ----

function Get-PimArmSqlVnetRules {
    <# az sql server vnet-rule list -s S : every rule (.name, .properties.virtualNetworkSubnetId). #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server)
    $r = Invoke-PimSetupArm -Path (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server 'virtualNetworkRules') -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull
    return @($r | Where-Object { $_ })
}

function New-PimArmSqlVnetRule {
    <# az sql server vnet-rule create -n N --subnet ID [--ignore-missing-endpoint] : PUT, waited on. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Server,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$SubnetId, [switch]$IgnoreMissingEndpoint)
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Sql/servers' $Server "virtualNetworkRules/$Name"
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ properties = @{ virtualNetworkSubnetId = $SubnetId; ignoreMissingVnetServiceEndpoint = [bool]$IgnoreMissingEndpoint } } -ApiVersion (Get-PimSetupApiVersion sql))
    [void](Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion sql))
}

# ---- Key Vault data plane ----

function Get-PimKeyVaultSecretValue {
    <#
      az keyvault secret show|download --vault-name V -n N : the secret's VALUE (for a certificate: the PFX, base64), over the
      vault's data plane with an Entra token. '' when it cannot be read (reason in $global:PimSetupRestLastError). Never printed.
    #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name)
    $r = Invoke-PimSetupRest -Url "https://$VaultName.vault.azure.net/secrets/$Name`?api-version=$(Get-PimSetupApiVersion keyVaultData)" -Resource 'https://vault.azure.net' -ErrorAsNull
    if ($r) { return "$($r.value)" }
    return ''
}

# ---- Container Apps: environment certificates, custom host names ----

function Set-PimArmAcaEnvCertificate {
    <#
      az containerapp env certificate upload --certificate-file PFX --certificate-name N [--password P] : PUT of the
      environment's certificates/N with the PFX (base64) -- returns the certificate resource (its .id binds a host name).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$EnvironmentName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$PfxBase64, [string]$Password, [string]$Location)
    $loc = "$Location".Trim()
    if (-not $loc) { $loc = "$((Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvironmentName).location)" }
    $props = @{ value = $PfxBase64 }
    if ("$Password") { $props.password = "$Password" }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $EnvironmentName "certificates/$Name"
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = $loc; properties = $props } -ApiVersion (Get-PimSetupApiVersion aca))
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion aca)
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "the certificate '$Name' was not accepted by environment '$EnvironmentName' ($st)." }
    Invoke-PimSetupArm -Path $id -ApiVersion (Get-PimSetupApiVersion aca)
}

function New-PimArmAcaManagedCertificate {
    <#
      The free managed certificate `az containerapp hostname bind --validation-method CNAME` requests: PUT of the
      environment's managedCertificates/N (subjectName = the host name, CNAME validation), waited on (validation takes
      minutes). Returns the certificate resource.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$EnvironmentName,
          [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$HostName, [string]$Location, [int]$TimeoutSeconds = 1200)
    $loc = "$Location".Trim()
    if (-not $loc) { $loc = "$((Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvironmentName).location)" }
    $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $EnvironmentName "managedCertificates/$Name"
    [void](Invoke-PimSetupArm -Method PUT -Path $id -Body @{ location = $loc; properties = @{ subjectName = $HostName; domainControlValidation = 'CNAME' } } -ApiVersion (Get-PimSetupApiVersion aca))
    $st = Wait-PimArmProvisioned -Path $id -ApiVersion (Get-PimSetupApiVersion aca) -TimeoutSeconds $TimeoutSeconds
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "the managed certificate for '$HostName' did not issue ($st) -- are the CNAME and TXT (asuid) records in public DNS?" }
    Invoke-PimSetupArm -Path $id -ApiVersion (Get-PimSetupApiVersion aca)
}

function Set-PimArmAcaAppCustomDomain {
    <#
      az containerapp hostname add (no -CertificateId: binding Disabled) | az containerapp hostname bind --certificate C
      (SniEnabled with that certificate id): read-modify-write of configuration.ingress.customDomains -- every other host
      name, the ingress and the secrets (with their values) are kept.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$HostName, [string]$CertificateId)
    Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Mutate {
        param($cfg)
        # $HostName / $CertificateId resolve dynamically from this function's scope (no bound closure -- see Set-PimArmAcaAppSecret).
        $keep = @(@($cfg.ingress.customDomains) | Where-Object { $_ -and "$($_.name)" -ine $HostName })
        $d = [ordered]@{ name = $HostName; bindingType = $(if ("$CertificateId".Trim()) { 'SniEnabled' } else { 'Disabled' }) }
        if ("$CertificateId".Trim()) { $d.certificateId = "$CertificateId".Trim() }
        $cfg.ingress | Add-Member -NotePropertyName customDomains -NotePropertyValue (@($keep) + @([pscustomobject]$d)) -Force
    }
}

function Set-PimArmAcaJobEnvVars {
    <#
      az containerapp job update --container-name C --set-env-vars K=V ... : read-modify-write of ONE container's env (every
      other variable, secret ref and container stays -- --set-env-vars ADDS OR UPDATES), one PATCH of the template, waited on.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][hashtable]$Env, [string]$ContainerName)
    $job = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $job) { throw "container apps job '$Name' not found in $ResourceGroup." }
    $cs = @($job.properties.template.containers)
    $t = if ("$ContainerName".Trim()) { @($cs | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1 } elseif ($cs.Count -eq 1) { $cs[0] } else { $null }
    if (-not $t) { throw "container apps job '$Name': cannot tell which of $($cs.Count) containers to change -- pass -ContainerName." }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($t.env)) { if ($e -and -not $Env.ContainsKey("$($e.name)")) { $list.Add($e) } }
    foreach ($k in $Env.Keys) { $list.Add([pscustomobject]@{ name = "$k"; value = "$($Env[$k])" }) }
    $t | Add-Member -NotePropertyName env -NotePropertyValue @($list.ToArray()) -Force
    Set-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -Resource @{ properties = @{ template = $job.properties.template } }
}

function Get-PimAcrManifestTags {
    <# az acr repository show -n R --image REPO@sha256:... --query tags : the tags pointing at that digest, @() when unreadable. #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string]$Digest)
    try {
        $r = Invoke-PimAcrData -LoginServer $LoginServer -Repository $Repository -Path "/acr/v1/$Repository/_manifests/$Digest"
        return @(@($r.manifest.tags) | Where-Object { "$_".Trim() })
    } catch { $global:PimSetupRestLastError = "$($_.Exception.Message)"; return @() }
}

# ---- Microsoft Graph: an application's certificate credentials, a sign-in as another identity ----

function ConvertTo-PimKeyIdentifierHex {
    # PURE. Graph's keyCredential.customKeyIdentifier is the certificate thumbprint's BYTES, base64 -- az printed it as hex.
    param([AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    if ($v -match '^[0-9a-fA-F]{40}$') { return $v.ToUpperInvariant() }
    try { return (([Convert]::FromBase64String($v) | ForEach-Object { $_.ToString('X2') }) -join '') } catch { return $v.ToUpperInvariant() }
}

function Get-PimGraphAppCertificateKeyId {
    <# az ad app credential list --id X --cert --query "[?customKeyIdentifier=='THUMB'].keyId" : the keyId bound for -Thumbprint, or ''. #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$Thumbprint)
    $app = Get-PimGraphApplication -Id $Id -ErrorAsNull
    $t = ("$Thumbprint" -replace '\s', '').ToUpperInvariant()
    foreach ($k in @($app.keyCredentials | Where-Object { $_ })) {
        if ((ConvertTo-PimKeyIdentifierHex -Value "$($k.customKeyIdentifier)") -eq $t) { return "$($k.keyId)" }
    }
    return ''
}

function Add-PimGraphAppCertificate {
    <#
      az ad app credential reset --id X --cert @file.cer --append --years N : PATCH keyCredentials with the existing entries
      (as Graph returns them, by keyId) plus the new certificate (DER, base64). Callers only aim this at a registration the
      same run created (New-PimDeployIdentity) -- an existing identity's credentials are never touched.
    #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][byte[]]$CertificateDer, [int]$Years = 2)
    $app = Get-PimGraphApplication -Id $Id
    if (-not $app) { throw "application '$Id' not found." }
    $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $CertificateDer)
    $end = $x.NotAfter.ToUniversalTime()
    $cap = (Get-Date).ToUniversalTime().AddYears([Math]::Max(1, $Years))
    if ($end -gt $cap) { $end = $cap }
    $keep = @(@($app.keyCredentials | Where-Object { $_ }) | ForEach-Object { @{ keyId = "$($_.keyId)"; type = "$($_.type)"; usage = "$($_.usage)" } })
    $new = @{ type = 'AsymmetricX509Cert'; usage = 'Verify'; key = [Convert]::ToBase64String($CertificateDer); endDateTime = $end.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    [void](Invoke-PimSetupGraph -Method PATCH -Path "/applications/$($app.id)" -Body @{ keyCredentials = @($keep) + @($new) })
}

function Test-PimSignInAs {
    <#
      az login --service-principal -u APP --tenant T --certificate PEM (+ az rest GET -GraphProbePath) in a throwaway profile:
      can THAT identity sign in -- and, with -GraphProbePath, read the directory -- right now? PIM-Rest mints the token for the
      named identity (certificate from the store by thumbprint, forced fresh: a cached token predates a grant); the caller's own
      session is untouched. Returns @{ signedIn; read; error }. Test seam: $global:PIM_SetupSignInStub = { param($TenantId, $ClientId, $Thumbprint, $GraphProbePath) @{...} }.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$CertThumbprint, [string]$GraphProbePath)
    if ($global:PIM_SetupSignInStub) { return (& $global:PIM_SetupSignInStub $TenantId $ClientId $CertThumbprint $GraphProbePath) }
    $out = @{ signedIn = $false; read = $false; error = '' }
    try { $tok = Get-PimRestToken -Resource 'graph' -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force; $out.signedIn = [bool]"$tok".Trim() }
    catch { $out.error = "$($_.Exception.Message)"; return $out }
    if (-not $out.signedIn -or -not "$GraphProbePath".Trim()) { return $out }
    try {
        $null = Invoke-RestMethod -Method GET -Uri ("https://graph.microsoft.com/v1.0" + "$GraphProbePath".Trim()) -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 60 -ErrorAction Stop
        $out.read = $true
    } catch { $out.error = "$($_.Exception.Message)" }
    return $out
}
