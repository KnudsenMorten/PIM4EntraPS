#Requires -Version 5.1
<#
.SYNOPSIS
    71.33 -- the SIGNED-IN (interactive) identity for the one-shot MSP build and the setup steps it runs.

.DESCRIPTION
    Operator 2026-09-17: "I thought I could just do interactive login to deploy." A customer deploys by signing in
    with `az login` as a human administrator; certificates are the MSP management host's automation pattern only. So
    every step the build runs inside ONE tenant accepts -UseSignedInAccount (or, where the script already had that
    convention, simply no credential) and then authenticates as the account signed in to az -- no certificate, no
    secret, nothing written to disk by this code, and no token ever printed or logged.

    WHAT IS ASSERTED BEFORE ANYTHING IS USED (a wrong default az context on a multi-tenant machine is a real trap):
      * the az account for the named subscription is a USER (a service principal is refused -- that is the certificate
        mode's job, and a signed-in SPN would silently change who the audit trail names);
      * its tenant equals the build config's tenantId, and the subscription is the one named explicitly;
      * every token minted from it (ARM, SQL) is decoded and its tenant and user-ness checked;
      * no environment variable is set that would make a token call quietly authenticate as somebody else
        (AZURE_CLIENT_SECRET, PIM_CERT_THUMBPRINT, a managed identity endpoint ...).

    SQL: Azure SQL here is Entra-only, so the signed-in user needs database rights -- by being a MEMBER of the SQL admin
    group (grp-pim-sql-admins) that is the server's Entra admin. Invoke-PimSignedInSqlAdminMembership adds the user as a
    member (members-only: it never creates the group and never moves the admin).
    TRAP: an Entra token carries group membership as of when it was issued, and az caches tokens for up to about an
    hour. A user added to the group in THIS run may be refused by SQL until their token refreshes -- the helper says so.

    Pure parts are offline-tested in tests/Test-PimMspBuild.ps1 (section S).
#>

$script:PimSignedInGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
# Environment variables that make a token call authenticate as SOMEBODY ELSE than the signed-in user.
$script:PimSignedInConflictVars = @('AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH', 'AZURE_FEDERATED_TOKEN_FILE',
                                    'PIM_CERT_THUMBPRINT', 'IDENTITY_ENDPOINT', 'MSI_ENDPOINT')

function ConvertFrom-PimJwtClaims {
    # PURE. The claims of a JWT (never validates the signature -- this is only used to ASSERT who a token is for).
    param([string]$Token)
    try {
        $seg = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/')
        while ($seg.Length % 4) { $seg += '=' }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json)
    } catch { return $null }
}

function Test-PimSignedInAccount {
    <#
      PURE. Judge an `az account show` object for the signed-in build. Returns @{ ok; reason; userName }.
      Refused: no account, a service principal / managed identity, another tenant, another subscription.
    #>
    param([object]$Account, [string]$TenantId, [string]$SubscriptionId)
    $want = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
    if ($want -notmatch $script:PimSignedInGuid -or $sub -notmatch $script:PimSignedInGuid) {
        return @{ ok = $false; reason = 'the tenant id and the subscription id must both be given explicitly (GUIDs) -- a signed-in build never relies on the default az context' }
    }
    if ($null -eq $Account -or -not "$($Account.id)".Trim()) {
        return @{ ok = $false; reason = "no az sign-in covers subscription $sub. Sign in first: az login --tenant $want" }
    }
    $type = "$($Account.user.type)".Trim().ToLowerInvariant()
    $name = "$($Account.user.name)".Trim()
    if ($type -ne 'user') {
        return @{ ok = $false; reason = ("az is signed in as a $(if ($type) { $type } else { 'non-user account' }) ('$name'), not a person. " +
                 'The signed-in build runs as the administrator at the keyboard; an application identity belongs in deployIdentity (certificate mode).') }
    }
    if ("$($Account.tenantId)".Trim().ToLowerInvariant() -ne $want) {
        return @{ ok = $false; reason = "the az sign-in for subscription $sub is in tenant '$($Account.tenantId)', but the build config names tenant '$want' -- REFUSING (a wrong default context acts in somebody else's directory)" }
    }
    if ("$($Account.id)".Trim().ToLowerInvariant() -ne $sub) {
        return @{ ok = $false; reason = "az answered for subscription '$($Account.id)', not the requested '$sub' -- REFUSING" }
    }
    return @{ ok = $true; reason = "signed in as $name (tenant $want, subscription $sub)"; userName = $name }
}

function Test-PimSignedInToken {
    <#
      PURE. Assert a token belongs to a signed-in USER of -TenantId. Returns @{ ok; reason; objectId; userName; tenantId }.
      An application token (idtyp=app, or no user claims) is refused: that is a different principal wearing the same call.
    #>
    param([string]$Token, [string]$TenantId)
    $c = ConvertFrom-PimJwtClaims -Token $Token
    if (-not $c) { return @{ ok = $false; reason = 'the token could not be decoded' } }
    $tid = "$($c.tid)".Trim().ToLowerInvariant()
    if ($tid -ne "$TenantId".Trim().ToLowerInvariant()) { return @{ ok = $false; reason = "the token is for tenant '$tid', not '$TenantId' -- REFUSING" } }
    $upn = "$(if ($c.upn) { $c.upn } elseif ($c.unique_name) { $c.unique_name } elseif ($c.preferred_username) { $c.preferred_username } else { '' })".Trim()
    $idtyp = "$($c.idtyp)".Trim().ToLowerInvariant()
    if ($idtyp -eq 'app' -or (-not $upn -and $idtyp -ne 'user')) {
        return @{ ok = $false; reason = "the token is an APPLICATION token (appid '$($c.appid)'), not the signed-in user's -- REFUSING" }
    }
    if ("$($c.oid)".Trim() -notmatch $script:PimSignedInGuid) { return @{ ok = $false; reason = 'the token carries no user object id' } }
    return @{ ok = $true; reason = ''; objectId = "$($c.oid)".Trim().ToLowerInvariant(); userName = $upn; tenantId = $tid }
}

function Get-PimSignedInEnvironmentConflicts {
    # PURE given -Environment (a hashtable name -> value); by default reads this process. The names that are set.
    param([hashtable]$Environment)
    $out = @()
    foreach ($n in $script:PimSignedInConflictVars) {
        $v = if ($Environment) { $Environment[$n] } else { [Environment]::GetEnvironmentVariable($n) }
        if ("$v".Trim()) { $out += $n }
    }
    return @($out)
}

function Get-PimSignedInIdentity {
    <#
      Read and ASSERT the signed-in identity for one tenant + subscription. Returns @{ ok; reason; userName; objectId;
      tenantId; subscriptionId }. The ARM token is minted only to read the user's object id and is then discarded.
      -Az is the test seam: a scriptblock param([string[]]$AzArgs) returning az's stdout.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Az)
    if (-not $Az) { $Az = { param([string[]]$AzArgs) $ErrorActionPreference = 'Continue'; & az @AzArgs 2>$null } }
    $conf = @(Get-PimSignedInEnvironmentConflicts)
    if ($conf.Count) {
        return @{ ok = $false; reason = ("REFUSED: $($conf -join ', ') $(if ($conf.Count -eq 1) { 'is' } else { 'are' }) set in this session -- a token call would authenticate as " +
                 'that identity instead of the signed-in user. Clear them (Remove-Item Env:\<name>) or use the certificate mode.') }
    }
    $acct = $null
    try { $acct = ((& $Az @('account', 'show', '--subscription', "$SubscriptionId", '-o', 'json')) | Out-String | ConvertFrom-Json) } catch { $acct = $null }
    $a = Test-PimSignedInAccount -Account $acct -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $a.ok) { return $a }
    $tok = $null
    try { $tok = "$(((& $Az @('account', 'get-access-token', '--subscription', "$SubscriptionId", '--resource', 'https://management.azure.com/', '-o', 'json')) | Out-String | ConvertFrom-Json).accessToken)" } catch { $tok = $null }
    if (-not "$tok".Trim()) { return @{ ok = $false; reason = "az could not issue a token for subscription $SubscriptionId (sign in again: az login --tenant $TenantId)" } }
    $t = Test-PimSignedInToken -Token $tok -TenantId $TenantId
    $tok = $null
    if (-not $t.ok) { return $t }
    return @{ ok = $true; reason = $a.reason; userName = $(if ($t.userName) { $t.userName } else { $a.userName }); objectId = $t.objectId
              tenantId = "$TenantId".Trim().ToLowerInvariant(); subscriptionId = "$SubscriptionId".Trim().ToLowerInvariant() }
}

function Set-PimSignedInGlobals {
    <#
      Make the engine's token helpers (Get-PimRestToken, New-PimSqlConnection) take the signed-in az path in THIS
      process: clear every application-identity global, pin the tenant, and switch the managed-identity probe off (a
      deploy host that is an Azure VM has a managed identity of its own, and it would otherwise win).
    #>
    param([Parameter(Mandatory)][string]$TenantId)
    foreach ($n in 'PIM_ClientId', 'PIM_ClientSecret', 'PIM_CertThumbprint', 'PIM_SqlClientId', 'PIM_SqlClientSecret', 'PIM_SqlCertThumbprint', 'PIM_SqlAccessToken', 'PIM_UseManagedIdentity') {
        Set-Variable -Scope Global -Name $n -Value $null
    }
    $global:PIM_TenantId = "$TenantId".Trim()
    $global:PIM_NoManagedIdentity = $true
    $global:PIM_UseGraphSdk = $false
    $global:PIM_SignedInAccount = $true
}

function Connect-PimSignedInSql {
    <#
      Prepare THIS process to reach Azure SQL as the signed-in user, and prove the token is right before any statement
      runs. PIM-Rest.ps1 must be loaded. Returns @{ userName; objectId }. The token itself stays in the engine's
      in-memory cache and is never returned, printed or written.
    #>
    param([Parameter(Mandatory)][string]$TenantId)
    $conf = @(Get-PimSignedInEnvironmentConflicts)
    if ($conf.Count) { throw "REFUSED: $($conf -join ', ') set in this session -- the SQL token would be minted for that identity, not the signed-in user." }
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { throw 'Connect-PimSignedInSql: engine\_shared\PIM-Rest.ps1 is not loaded.' }
    Set-PimSignedInGlobals -TenantId $TenantId
    $tok = Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId
    $t = Test-PimSignedInToken -Token "$tok" -TenantId $TenantId
    $tok = $null
    if (-not $t.ok) { throw "SQL as the signed-in user: $($t.reason)" }
    $global:PIM_SetupActor = $(if ($t.userName) { $t.userName } else { $t.objectId })
    return @{ userName = $t.userName; objectId = $t.objectId }
}

function Invoke-PimSignedInSqlAdminMembership {
    <#
      Make the signed-in user a MEMBER of the SQL admin group of -SqlServerName (members-only: never creates the group,
      never moves the Entra admin). Returns @{ ok; blocked; added; reason }. Blocked = the server's admin is not the
      group, so membership would grant nothing -- the caller must refuse with that reason.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$SqlServerName, [Parameter(Mandatory)][string]$UserObjectId, [string]$GroupName = 'grp-pim-sql-admins')
    if (-not (Get-Command Invoke-PimSqlAdminGroupStep -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_PimSqlAdminGroup.ps1') }
    $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId
    $srv = ("$SqlServerName".Trim() -split '\.')[0]
    $sqlRg = $ResourceGroup
    if (Get-Command Resolve-PimSqlServerFromFqdn -ErrorAction SilentlyContinue) {
        try { $res = Resolve-PimSqlServerFromFqdn -Arm $inv.Arm -SubscriptionId $SubscriptionId -Server $srv; if ($res) { $sqlRg = $res.resourceGroup; $srv = $res.name } } catch { }
    }
    $r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
            -SqlResourceGroup $sqlRg -SqlServerName $srv -GroupName $GroupName -UpdateJobName '' -NoDiscovery -Mode membersOnly `
            -ExtraMembers @([pscustomobject]@{ objectId = "$UserObjectId".Trim(); label = 'the signed-in administrator' })
    Write-PimSqlAdminGroupReport -Result $r
    $added = @(@($r.added) | Where-Object { "$($_.objectId)" -ieq "$UserObjectId".Trim() }).Count -gt 0
    if (-not $r.ok) { return @{ ok = $false; blocked = $false; added = $added; reason = "could not make the signed-in user a member of '$GroupName': $(@($r.problems) -join '; ')" } }
    if ($r.blocked) { return @{ ok = $true; blocked = $true; added = $false; reason = "the Entra admin of $srv is not '$GroupName' ($($r.blocked)) -- membership grants nothing there. Converge the server onto the group first (Initialize-PimSqlAdminGroup.ps1), or make the signed-in user the Entra admin." } }
    if ($added) {
        Write-Host ("    NOTE: you were ADDED to '$GroupName' just now. An Entra token carries group membership as of when it was issued, " +
                    'and az caches tokens for up to about an hour -- if SQL refuses the next step, sign in again (az logout; az login --tenant <tenant>) and resume.') -ForegroundColor Yellow
    }
    return @{ ok = $true; blocked = $false; added = $added; reason = '' }
}
