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
      * Assert-PimSetupRegion     -- region guard: West Europe / Denmark East /
                                     Sweden Central only; France is explicitly
                                     refused (data-residency).
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
      * Set-PimVnetPeering        -- BUG-49: peer the PIM spoke VNet to the hub, BOTH
                                     directions, and verify both read Connected.
      * Set-PimPrivateDnsZone     -- BUG-49: publish the ACA env default domain to the
                                     env static IP in an Azure Private DNS zone and link
                                     it to the VNets that must resolve it.
      * Grant-PimMiAzureRbac      -- BUG-51: grant a workload identity its ARM role
                                     (Reader by default) so PIM's Azure half is not blind.
      * Resolve-PimAcrImageDigest -- BUG-40: resolve a mutable tag to the immutable
                                     digest it points at, so a deploy writes content,
                                     not a pointer. Pairs with the pure reference
                                     helpers in engine/_shared/PIM-ImageRef.ps1.

    Everything is REST / az-CLI based and PS 5.1-safe (no ?./??, no
    RSA.ImportFromPem, no PS7-only members). No real tenant/subscription/customer
    values are baked in -- callers pass them.
#>

# The PURE image-reference helpers (Test-PimImageDigest / New-PimImageReference /
# Test-PimImageDeployed). Kept in engine/_shared because the deploy scripts, the update
# scripts and the offline tests all need the same definition of "is the running image the
# one we deployed" -- and that question must have exactly one answer.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-ImageRef.ps1')

# The PURE reachability planners (peering pairs / private-DNS record set / ARM role
# assignments). Same reason as above: the deploy scripts and the offline tests must share
# one definition of "what makes a deployed environment reachable and Azure-sighted".
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-Reachability.ps1')

# Region allow-list. EU-only hosting. France is REFUSED (data-residency).
# swedencentral added 2026-08-09 (operator decision): the 28-tenant test estate is provisioned
# there because a FRESH subscription refuses new resources in westeurope/northeurope -- see
# New-PimHostingPrerequisites.ps1's -Location default. Until that was allowed here, step 3 built
# the estate in a region Setup-PimContainers then threw on, so the container steps could never
# run against what the estate actually is. Sweden Central is EU; the explicit denial is France.
$script:PimAllowedRegions = @('westeurope','denmarkeast','swedencentral')
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
        throw "Region '$Location' is not allowed for PIM hosting (data residency). Use West Europe ('westeurope'), Denmark East ('denmarkeast') or Sweden Central ('swedencentral') -- never France."
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
        # ONE of these. Secret was Mandatory, which made a CLIENT SECRET structurally required to
        # deploy -- against the repo-root rule ("authenticate as its SPN using a CERTIFICATE, never
        # a client secret") and impossible to satisfy in a tenant whose admin SPN is cert-only.
        # Get-PimRestToken has supported -CertThumbprint all along; only this signature forced the
        # secret. Added 2026-08-09 while deploying PIM §34.
        [string]$SqlAdminClientSecret,
        [string]$SqlAdminCertThumbprint
    )
    if ($SqlAdminClientSecret -and $SqlAdminCertThumbprint) { throw 'Grant-PimMiSql: pass EITHER -SqlAdminClientSecret OR -SqlAdminCertThumbprint, not both.' }
    if (-not $SqlAdminClientSecret -and -not $SqlAdminCertThumbprint) { throw 'Grant-PimMiSql: one of -SqlAdminClientSecret / -SqlAdminCertThumbprint is required.' }
    $global:PIM_TenantId = $TenantId
    $global:PIM_ClientId = $SqlAdminClientId
    if ($SqlAdminCertThumbprint) {
        # Clear any inherited secret so a stale $global:PIM_ClientSecret cannot silently win inside
        # Get-PimRestToken's fallback chain -- that would authenticate as something other than what
        # this call asked for, and the log would not show it.
        $global:PIM_ClientSecret   = $null
        $global:PIM_CertThumbprint = $SqlAdminCertThumbprint
        $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $SqlAdminClientId -CertThumbprint $SqlAdminCertThumbprint -Force
    } else {
        $global:PIM_ClientSecret   = $SqlAdminClientSecret
        $global:PIM_SqlAccessToken = Get-PimRestToken -Resource 'https://database.windows.net' -ClientId $SqlAdminClientId -ClientSecret $SqlAdminClientSecret -Force
    }
    $sid = ConvertTo-PimSqlSidFromAppId -AppId $MiAppId
    $cs  = "Server=tcp:$SqlServerFqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $c = New-PimSqlConnection -ConnectionString $cs
    $c.Open()
    try {
        # BUG-47 -- this used to be an unconditional DROP USER + CREATE USER, which is NOT
        # idempotent and fails on the FIRST re-run of a working environment:
        #
        #   "The database principal owns a schema in the database, and cannot be dropped.
        #    User, group, or role 'ca-pim-manager' already exists in the current database."
        #
        # The user holds db_ddladmin (it has to -- it applies the schema), so as soon as it
        # creates a schema it OWNS that schema, and an owner cannot be dropped. Measured on the
        # mfnpr production deploy: the very re-run that was fixing an unrelated defect died here,
        # and it would fail identically on every customer whose environment has ever been used.
        #
        # The drop was never the point -- the point is that the contained user maps to the RIGHT
        # SID. So: only recreate when the SID actually differs, and when it does, hand the owned
        # schemas to dbo first so the drop can proceed. Role membership is applied unconditionally
        # but guarded, because ALTER ROLE on an existing member is a no-op we should not depend on.
        $b = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$DbUserName' AND sid = $sid)
BEGIN
    IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name='$DbUserName')
    BEGIN
        -- Same NAME, different SID: the identity was rebuilt, so the user genuinely must be
        -- replaced. Transfer anything it owns to dbo first, or the DROP cannot succeed.
        DECLARE @reassign NVARCHAR(MAX);
        SELECT @reassign = STRING_AGG('ALTER AUTHORIZATION ON SCHEMA::' + QUOTENAME(s.name) + ' TO [dbo];', ' ')
        FROM sys.schemas s
        JOIN sys.database_principals p ON s.principal_id = p.principal_id
        WHERE p.name = '$DbUserName';
        IF @reassign IS NOT NULL EXEC sp_executesql @reassign;
        DROP USER [$DbUserName];
    END
    CREATE USER [$DbUserName] WITH SID = $sid, TYPE = E;
END
IF IS_ROLEMEMBER('db_datareader','$DbUserName') = 0 ALTER ROLE db_datareader ADD MEMBER [$DbUserName];
IF IS_ROLEMEMBER('db_datawriter','$DbUserName') = 0 ALTER ROLE db_datawriter ADD MEMBER [$DbUserName];
IF IS_ROLEMEMBER('db_ddladmin','$DbUserName')   = 0 ALTER ROLE db_ddladmin   ADD MEMBER [$DbUserName];
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
    # BUG-82: reading the tenant's default verified domain (/domains) needs its own role -- none of
    # the eight above covers it, not even Directory.Read.All. The managed-tenant downlink resolves
    # that domain to build synced admins' UPNs (IMP-12), and without it the engine SPN gets
    #   GET /v1.0/domains -> 403 Authorization_RequestDenied
    # so the downlink refuses to stage admins rather than guess a domain -- correct, and fatal to
    # the whole S6 apply. Id read from the live Graph service principal, not from memory.
    'Domain.Read.All'                          = 'dbb9058a-0e50-45d7-ae91-66909b5d4664'
}

function Get-PimGraphAppRoleMap {
    [CmdletBinding()] param()
    $h = @{}; foreach ($k in $script:PimGraphAppRoles.Keys) { $h[$k] = $script:PimGraphAppRoles[$k] }
    return $h
}

function Grant-PimMiGraph {
    <#
      BUG-45 -- a DENIED app-role assignment is not a warning, it is a broken deployment.

      This used to swallow every POST failure into Write-Warning. An identity that silently
      failed to get Directory.Read.All still produced a "successful" deploy, and the breakage
      only surfaced later as 403s inside the container -- where it reads like an engine bug,
      not a grant that never happened. Measured on mfnpr's tick Job: zero app-role assignments,
      four green executions, no work done.

      'Already exists' remains the ONE tolerated outcome, because re-running the deploy is
      normal and must stay idempotent. Everything else now throws and names the role.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$MiObjectId)
    $gtok = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null
    if (-not $gtok) { throw "Grant-PimMiGraph: no Graph token (run 'az login' as a role-assigner)." }
    $gh = @{ Authorization = "Bearer $gtok"; 'Content-Type' = 'application/json' }
    $graphSp = (Invoke-RestMethod -Headers $gh -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'").value[0]
    # 🪤 DO NOT go back to "POST everything and tolerate an 'already exists' error string". Graph
    # answers a duplicate assignment with **HTTP 400**, and the explanatory text ("Permission being
    # assigned already exists on the object") is in the response BODY -- `$_.Exception.Message` is
    # only "Response status code does not indicate success: 400 (Bad Request)." So a message match
    # on 'already' can never fire, which is why the old code needed to swallow every failure to
    # stay idempotent, and why swallowing them hid a genuinely un-granted identity. Reading the
    # current assignments first removes the guesswork: assign only what is missing, and then any
    # failure that remains is real.
    $assignUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$MiObjectId/appRoleAssignments"
    function Get-PimAssignedRoleIds {
        param($Headers, $Uri)
        try { return @((Invoke-RestMethod -Headers $Headers -Uri $Uri).value | ForEach-Object { "$($_.appRoleId)" }) }
        catch { return $null }   # cannot read => treat every role as missing (fail-safe)
    }
    $have = Get-PimAssignedRoleIds -Headers $gh -Uri $assignUri
    if ($null -eq $have) { $have = @() }

    $failed = [System.Collections.Generic.List[string]]::new()
    $granted = 0
    foreach ($r in $script:PimGraphAppRoles.GetEnumerator()) {
        if ("$($r.Value)" -in $have) { continue }   # already assigned -- nothing to do
        try {
            Invoke-RestMethod -Method POST -Headers $gh -Uri $assignUri `
                -Body (@{ principalId = $MiObjectId; resourceId = $graphSp.id; appRoleId = $r.Value } | ConvertTo-Json) -ErrorAction Stop | Out-Null
            $granted++
        } catch {
            # The BODY carries the reason; the exception message carries only the status line.
            $body = ''
            try { $body = "$($_.ErrorDetails.Message)" } catch { }
            $failed.Add("$($r.Key): $($_.Exception.Message)$(if ("$body".Trim()) { " -- $body" })")
        }
    }
    if ($failed.Count) {
        # Re-read before condemning: a role can land and be reported as failed if the write raced a
        # read, and a directory that already has the assignment is a success no matter what the POST
        # said. Only a role that is STILL absent is a real failure.
        $now = Get-PimAssignedRoleIds -Headers $gh -Uri $assignUri
        if ($null -ne $now) {
            $stillMissing = @($script:PimGraphAppRoles.GetEnumerator() | Where-Object { "$($_.Value)" -notin $now })
            if (-not $stillMissing.Count) {
                Write-Host "    all $($script:PimGraphAppRoles.Count) Graph app-roles present (POST errors were duplicates)" -ForegroundColor DarkGray
                return
            }
            throw ("Grant-PimMiGraph: $($stillMissing.Count) of $($script:PimGraphAppRoles.Count) Graph app-roles are " +
                   "MISSING on identity $MiObjectId after the grant, so it cannot read/write the directory. " +
                   "Missing: " + (($stillMissing | ForEach-Object { $_.Key }) -join ', ') + ". " +
                   "The deploying identity needs AppRoleAssignment.ReadWrite.All. Errors: " + ($failed -join ' | '))
        }
        throw ("Grant-PimMiGraph: $($failed.Count) Graph app-role assignment(s) failed for identity $MiObjectId " +
               "and the current assignments could not be read back to confirm. Errors: " + ($failed -join ' | '))
    }
    if ($granted) { Write-Host "    granted $granted new Graph app-role(s)" -ForegroundColor DarkGray }
}

function Resolve-PimMiAppId {
    <#
      BUG-44 -- a managed identity's service principal is EVENTUALLY consistent in the directory.

      MEASURED on mfnpr 2026-08-09: `az containerapp job create` returned, the Job's
      system-assigned SP was stamped at 22:59:27, and `az ad sp show` seconds later returned
      NOTHING -- so the deploy threw "could not resolve an appId" and stopped before the SQL and
      Graph grants. The identical lookup on the identical objectId succeeds now. The manager app
      90 lines earlier survived the same call only because `containerapp create` blocks on
      provisioning and therefore gave the directory time; the Job create returns immediately.

      This was previously mis-recorded as a PERMISSIONS gap (§34.2b) and nearly bought an
      identity-model change plus a per-tenant admin-consent step for a problem that is a race.
      The evidence against that reading: the SAME deploying SPN granted the manager's identity
      eight Graph app-roles in the SAME run.

      Retries are therefore the fix, and they must be BOUNDED -- an identity that never appears
      is a real failure and has to stop the deploy rather than hang it.

      -Lookup / -Sleep are injectable so the retry policy is provable offline, with no az and no
      real waiting (tests/Test-PimMiAppIdRetry.ps1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        # What this identity belongs to, for the error message: "ca-pim-tick", "ca-pim-manager".
        [Parameter(Mandatory)][string]$What,
        [int]$MaxAttempts          = 8,
        [int]$InitialDelaySeconds  = 2,
        [int]$MaxDelaySeconds      = 30,
        # Default: the real directory read. Returns '' when the SP is not visible yet.
        [scriptblock]$Lookup = { param($oid) "$(az ad sp show --id $oid --query appId -o tsv 2>$null)".Trim() },
        [scriptblock]$Sleep  = { param($sec) Start-Sleep -Seconds $sec }
    )
    if ($MaxAttempts -lt 1) { throw 'Resolve-PimMiAppId: -MaxAttempts must be at least 1.' }
    $delay = $InitialDelaySeconds
    $waited = 0
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $appId = "$(& $Lookup $ObjectId)".Trim()
        if ($appId) {
            if ($attempt -gt 1) { Write-Host "    directory caught up after $waited s ($attempt attempts)" -ForegroundColor DarkGray }
            return $appId
        }
        if ($attempt -eq $MaxAttempts) { break }
        Write-Host "    identity $ObjectId not in the directory yet -- retry in ${delay}s ($attempt/$MaxAttempts)" -ForegroundColor DarkGray
        & $Sleep $delay
        $waited += $delay
        $delay = [Math]::Min($delay * 2, $MaxDelaySeconds)
    }
    throw ("Could not resolve an appId for '$What' identity $ObjectId after $MaxAttempts attempts " +
           "over ${waited}s. A newly-created managed identity is eventually consistent, so a short " +
           "delay is normal -- this waited past that. Check that the identity exists and that the " +
           "deploying identity can read the directory (Directory.Read.All or equivalent).")
}

function Resolve-PimAcrImageDigest {
    <#
      BUG-40 -- resolve a MUTABLE tag to the IMMUTABLE digest it currently points at.

      This is the thin `az` half; every decision it feeds is made by the pure helpers in
      engine/_shared/PIM-ImageRef.ps1 (New-PimImageReference / Test-PimImageDeployed).

      Deploying by tag is what let a rebuilt image go un-pulled: ARM saw an unchanged image
      field, so no new revision was created and the platform kept the image it already had.
      Resolving here means the deploy writes content-addressed bytes, not a pointer.

      THROWS rather than falling back to the tag. Silent degradation is precisely what hid
      BUG-39/BUG-40, and the failure it would degrade into is not benign: if the tag cannot be
      resolved the image is not in the registry, so deploying it would ImagePullFailure anyway.
      Failing here names the real cause; failing there names the wrong one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AcrName,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Tag
    )
    $ref = "$Repository`:$Tag"
    # `az acr manifest show-metadata` is the current command; `az acr repository show` is the
    # older one that still ships. Try both before concluding the tag is absent -- an az version
    # difference must not read as "the image was never built".
    $digest = az acr manifest show-metadata -r $AcrName -n $ref --query digest -o tsv --only-show-errors 2>$null
    if (-not (Test-PimImageDigest -Digest "$digest".Trim())) {
        $digest = az acr repository show -n $AcrName --image $ref --query digest -o tsv --only-show-errors 2>$null
    }
    $digest = "$digest".Trim()
    if (-not (Test-PimImageDigest -Digest $digest)) {
        throw ("Could not resolve a digest for '$AcrName.azurecr.io/$ref' (got '$digest'). Either the tag " +
               "was never pushed, or this identity cannot read the registry. Refusing to deploy by tag as a " +
               "fallback -- a tag deploy can silently keep running the previous image (BUG-40).")
    }
    return $digest
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

function Set-PimVnetPeering {
    <#
      BUG-49 -- THE DEPLOY BUILT AN ISLAND.

      `New-PimHostingPrerequisites` creates an isolated spoke VNet and nothing ever peered it,
      so the production Manager had NO ROUTE FROM ANYWHERE while every resource-level check
      passed: app Succeeded, ingress reporting an FQDN, image verified. Reachability is the one
      property the resource graph cannot show.

      BOTH directions, always. A one-sided peering reads `Initiated` on the side you created and
      carries no traffic -- and whichever blade you happen to open shows a peering that exists.
      So this verifies the STATE of both, and a peering that is not `Connected` is a failure, not
      a warning: the whole point of the step is that the environment is reachable when it ends.

      Idempotent: an existing peering with the right remote is left alone.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SpokeVnetName,
        [Parameter(Mandatory)][string]$SpokeResourceGroup,
        [Parameter(Mandatory)][string]$SpokeSubscriptionId,
        [Parameter(Mandatory)][string]$HubVnetName,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [string]$HubSubscriptionId
    )
    # Read the address spaces so the PURE planner can refuse an overlap by name rather than
    # letting az refuse it with a message that names neither range. Unreadable => $null =>
    # the planner treats overlap as UNKNOWN and proceeds (Azure remains the backstop).
    $spokeCidr = az network vnet show -g $SpokeResourceGroup -n $SpokeVnetName --subscription $SpokeSubscriptionId `
                    --query "addressSpace.addressPrefixes[0]" -o tsv --only-show-errors 2>$null
    $hubSub    = $(if ("$HubSubscriptionId".Trim()) { $HubSubscriptionId } else { $SpokeSubscriptionId })
    $hubCidr   = az network vnet show -g $HubResourceGroup -n $HubVnetName --subscription $hubSub `
                    --query "addressSpace.addressPrefixes[0]" -o tsv --only-show-errors 2>$null

    $plan = Get-PimPeeringPlan -SpokeVnetName $SpokeVnetName -SpokeResourceGroup $SpokeResourceGroup `
                -SpokeSubscriptionId $SpokeSubscriptionId -HubVnetName $HubVnetName `
                -HubResourceGroup $HubResourceGroup -HubSubscriptionId $HubSubscriptionId `
                -SpokeAddressSpace "$spokeCidr".Trim() -HubAddressSpace "$hubCidr".Trim()
    if (-not $plan.ok) { throw "VNet peering refused: $($plan.reason)" }
    Write-Host "    $($plan.reason)" -ForegroundColor DarkGray

    foreach ($p in $plan.pairs) {
        $existing = az network vnet peering show -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                        --subscription $p.subscriptionId --query "remoteVirtualNetwork.id" -o tsv --only-show-errors 2>$null
        if ("$existing".Trim() -and "$existing".Trim().ToLowerInvariant() -eq $p.remoteVnetId.ToLowerInvariant()) {
            Write-Host "    peering $($p.name): exists" -ForegroundColor DarkGray
        } elseif ($PSCmdlet.ShouldProcess("$($p.vnetName)/$($p.name)", "peer -> $($p.remoteVnetId)")) {
            if ("$existing".Trim()) {
                # A peering of the right NAME pointing at the WRONG VNet is worse than none: it
                # occupies the name, so every later "create" is a no-op and the environment stays
                # unreachable while a peering visibly exists.
                throw ("peering '$($p.name)' on $($p.vnetName) already points at $existing, not $($p.remoteVnetId). " +
                       "Refusing to leave a peering whose name says one thing and whose target says another -- " +
                       "delete it (az network vnet peering delete -g $($p.resourceGroup) --vnet-name $($p.vnetName) -n $($p.name)) and re-run.")
            }
            az network vnet peering create -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                --remote-vnet $p.remoteVnetId --allow-vnet-access --subscription $p.subscriptionId -o none --only-show-errors
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                throw "az network vnet peering create failed for '$($p.name)' on $($p.vnetName) (exit $LASTEXITCODE). Cross-subscription peering needs Network Contributor on BOTH sides."
            }
            Write-Host "    peering $($p.name): created" -ForegroundColor Green
        }
    }

    if ($WhatIfPreference) { return }
    # VERIFY THE STATE, not the create calls. `Initiated` is the exact shape of a half-built
    # peering, and it is indistinguishable from a working one unless you read peeringState.
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($p in $plan.pairs) {
        $state = az network vnet peering show -g $p.resourceGroup --vnet-name $p.vnetName -n $p.name `
                    --subscription $p.subscriptionId --query peeringState -o tsv --only-show-errors 2>$null
        Write-Host ("    {0,-40} {1}" -f $p.name, $(if ("$state".Trim()) { "$state".Trim() } else { 'UNREADABLE' })) -ForegroundColor DarkGray
        if ("$state".Trim() -ne 'Connected') { $bad.Add("$($p.name)=$(if ("$state".Trim()) { "$state".Trim() } else { 'unreadable' })") | Out-Null }
    }
    if ($bad.Count) {
        throw ("VNet peering is NOT Connected in both directions ($($bad -join ', ')). The Manager will have no " +
               "route from the hub, which every resource-level check will still report as a healthy deploy (BUG-49).")
    }
}

function Set-PimPrivateDnsZone {
    <#
      BUG-49, the other half -- A ROUTE WITHOUT A NAME IS STILL UNREACHABLE.

      An `--internal-only` ACA environment publishes its apps on the environment's default domain
      at ONE static private IP, and nothing off the ACA subnet resolves that name. Peering alone
      therefore produces a client that can route to the Manager and cannot find it.

      This mirrors what the tenant already had for the predecessor environment: a Private DNS zone
      named for the default domain, apex + wildcard + `*.internal` A records at the env static IP,
      linked to every VNet that must resolve it.

      Idempotent: find-or-create the zone, upsert each record set, find-or-create each link.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$EnvDomain,
        [Parameter(Mandatory)][string]$StaticIp,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string[]]$LinkVnetIds = @(),
        [string]$ManagerFqdn = ''
    )
    $plan = Get-PimPrivateDnsPlan -EnvDomain $EnvDomain -StaticIp $StaticIp -ResourceGroup $ResourceGroup `
                -LinkVnetIds $LinkVnetIds -ManagerFqdn $ManagerFqdn
    if (-not $plan.ok) { throw "private DNS refused: $($plan.reason)" }
    Write-Host "    $($plan.reason)" -ForegroundColor DarkGray
    foreach ($w in @($plan.warnings)) { Write-Warning "  $w" }

    if (-not $PSCmdlet.ShouldProcess($plan.zoneName, "private DNS zone -> $($plan.staticIp)")) { return }

    az network private-dns zone create -g $ResourceGroup -n $plan.zoneName --subscription $SubscriptionId `
        -o none --only-show-errors 2>$null | Out-Null
    $zoneOk = az network private-dns zone show -g $ResourceGroup -n $plan.zoneName --subscription $SubscriptionId `
                  --query name -o tsv --only-show-errors 2>$null
    if (-not "$zoneOk".Trim()) {
        throw "could not create or read private DNS zone '$($plan.zoneName)' in $ResourceGroup. Without it the Manager FQDN does not resolve for any client (BUG-49)."
    }

    foreach ($r in $plan.records) {
        # 🔴 READ BEFORE WRITING, and do NOTHING when it already matches.
        # The write below is delete-then-add, because `add-record` is create-or-append: a re-run
        # would STACK a second A record rather than replace one whose IP has moved, and only
        # delete-then-add converges when an ACA environment is recreated with a new static IP.
        # But on an environment that is ALREADY CORRECT -- which is every idempotent re-deploy,
        # and the common case -- that same delete would briefly remove the record the Manager is
        # reached through. A deploy that re-runs cleanly must not blink the name it just published.
        $have = @(az network private-dns record-set a show -g $ResourceGroup -z $plan.zoneName -n $r.name `
                      --subscription $SubscriptionId --query "aRecords[].ipv4Address" -o tsv --only-show-errors 2>$null)
        $have = @($have | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($have.Count -eq 1 -and $have[0] -eq $r.ipv4Address) {
            Write-Host ("    A {0,-12} -> {1}   (already correct)" -f $r.name, $r.ipv4Address) -ForegroundColor DarkGray
            continue
        }
        if ($have.Count) { Write-Host ("    A {0,-12} currently {1} -> replacing with {2}" -f $r.name, ($have -join ','), $r.ipv4Address) -ForegroundColor Yellow }
        az network private-dns record-set a delete -g $ResourceGroup -z $plan.zoneName -n $r.name `
            --subscription $SubscriptionId --yes -o none --only-show-errors 2>$null | Out-Null
        az network private-dns record-set a add-record -g $ResourceGroup -z $plan.zoneName -n $r.name `
            -a $r.ipv4Address --subscription $SubscriptionId -o none --only-show-errors
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "could not write A record '$($r.name)' in zone '$($plan.zoneName)' (exit $LASTEXITCODE)." }
        Write-Host ("    A {0,-12} -> {1}   ({2})" -f $r.name, $r.ipv4Address, $r.purpose) -ForegroundColor DarkGray
    }

    # 🔴 MATCH ON THE VNET, NOT ON THE LINK NAME. MEASURED against the live production zone
    # 2026-08-10: the existing link is named `cae-pim-mfnpr-dnslink`, this looked for
    # `link-vnet-platform`, concluded "missing", tried to create it, and Azure refused with
    # `Conflict: Private zone ... is already linked to the virtual network ...` -- failing the
    # whole deploy over a desired state that was ALREADY SATISFIED. Any environment whose link
    # was created by hand or under an older naming convention would have hit this on every run.
    # The link NAME is arbitrary metadata; the only thing that decides whether clients on a VNet
    # can resolve the zone is whether SOME link points at that VNet. Probe the capability being
    # used, not the artefact this script happens to name (the BUG-46 lesson).
    $linkedVnetIds = @(az network private-dns link vnet list -g $ResourceGroup -z $plan.zoneName `
                          --subscription $SubscriptionId --query "[].virtualNetwork.id" -o tsv --only-show-errors 2>$null)
    $linkedVnetIds = @($linkedVnetIds | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($l in $plan.links) {
        $want = "$($l.vnetId)".Trim().ToLowerInvariant()
        if ($linkedVnetIds -contains $want) {
            Write-Host "    link -> $(($l.vnetId -split '/')[-1]): already linked" -ForegroundColor DarkGray
            continue
        }
        az network private-dns link vnet create -g $ResourceGroup -z $plan.zoneName -n $l.name `
            -v $l.vnetId -e $(if ($l.registrationEnabled) { 'true' } else { 'false' }) `
            --subscription $SubscriptionId -o none --only-show-errors
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "could not link VNet '$($l.vnetId)' to zone '$($plan.zoneName)' (exit $LASTEXITCODE). Without the link, clients on that VNet cannot resolve the Manager."
        }
        Write-Host "    link $($l.name): created" -ForegroundColor Green
    }

    # Read back the record that actually matters. A zone with no A records looks like a
    # configured zone right up until the first client resolves NXDOMAIN.
    $apex = az network private-dns record-set a show -g $ResourceGroup -z $plan.zoneName -n '@' `
                --subscription $SubscriptionId --query "aRecords[0].ipv4Address" -o tsv --only-show-errors 2>$null
    if ("$apex".Trim() -ne $plan.staticIp) {
        throw "private DNS zone '$($plan.zoneName)' apex resolves to '$apex', not $($plan.staticIp). Do NOT assume the records landed (BUG-49)."
    }
    Write-Host "    zone verified: $($plan.zoneName) apex -> $apex" -ForegroundColor DarkGray
}

function Grant-PimMiAzureRbac {
    <#
      BUG-51 -- THE DIRECTORY HALF WORKED PERFECTLY AND THE AZURE HALF SAW NOTHING.

      The deploy granted these identities their GRAPH app-roles and no ARM rights whatsoever, so
      the tenant-cache job returned `entra-roles=146 aus=36 pim-groups=332 azure-scopes=0
      azure-rbac-roles=0` next to `ARM managementGroups list failed ... 403 AuthorizationFailed`.
      Nothing failed. There was simply nothing to see.

      This is the exact mirror of framework DOCS/REQUIREMENTS.md §10.0b -- "Global Administrator
      is a directory role and grants nothing in Azure" -- read in the other direction.

      Non-fatal BY DESIGN, unlike the Graph grant: the deploying identity frequently has enough
      rights to create resources and NOT enough to assign roles (role assignment needs User Access
      Administrator or Owner). Failing the whole deploy there would block environments that are
      otherwise correct -- so this WARNS, loudly and specifically, naming the az command to run.
      Pass -Required to make it fatal where the deploying identity is known to be able to do it.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$MiObjectId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string[]]$Roles = @('Reader'),
        [string]$ManagementGroupId = '',
        [switch]$Required
    )
    $plan = Get-PimAzureRbacPlan -Principals @(@{ name = $Name; objectId = $MiObjectId }) `
                -SubscriptionId $SubscriptionId -Roles $Roles -ManagementGroupId $ManagementGroupId
    if (-not $plan.ok) { throw "Azure RBAC refused: $($plan.reason)" }
    foreach ($w in @($plan.warnings)) { Write-Verbose "  Azure RBAC: $w" }

    $failed = New-Object System.Collections.Generic.List[string]
    $granted = 0
    foreach ($a in $plan.assignments) {
        $have = az role assignment list --assignee $a.principalId --scope $a.scope --role $a.role `
                    --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
        if ("$have".Trim() -eq $a.role) { continue }
        if (-not $PSCmdlet.ShouldProcess("$($a.principalName) @ $($a.scope)", "grant $($a.role)")) { continue }
        az role assignment create --assignee-object-id $a.principalId --assignee-principal-type ServicePrincipal `
            --role $a.role --scope $a.scope -o none --only-show-errors 2>$null
        # Read back rather than trust the exit code: a duplicate assignment exits non-zero
        # (RoleAssignmentExists) and IS success, and a silent no-op exits zero and is not.
        $now = az role assignment list --assignee $a.principalId --scope $a.scope --role $a.role `
                   --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
        if ("$now".Trim() -eq $a.role) { $granted++ }
        else { $failed.Add("$($a.role) @ $($a.scopeKind) $($a.scope)") | Out-Null }
    }

    if ($failed.Count) {
        $msg = ("Azure RBAC NOT granted to '$Name' ($MiObjectId): " + ($failed -join '; ') + ". " +
                "PIM's Azure half will be BLIND -- the tenant cache will report azure-scopes=0 " +
                "azure-rbac-roles=0 while the directory half looks perfect (BUG-51). Grant it with: " +
                "az role assignment create --assignee-object-id $MiObjectId --assignee-principal-type " +
                "ServicePrincipal --role Reader --scope /subscriptions/$SubscriptionId")
        if ($Required) { throw $msg }
        Write-Warning "  $msg"
        return
    }
    if ($granted) { Write-Host "    granted $granted Azure role assignment(s) to $Name" -ForegroundColor DarkGray }
    else { Write-Host "    Azure RBAC already present for $Name" -ForegroundColor DarkGray }
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
