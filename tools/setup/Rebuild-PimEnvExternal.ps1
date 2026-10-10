#Requires -Version 5.1
<#
.SYNOPSIS
    §33.0 B4 -- rebuild a PIM environment that was built INTERNAL-ONLY so it is EXTERNAL, without
    ever exposing the Manager unauthenticated. PLANS by default; changes nothing without -Apply.

.DESCRIPTION
    🔴 WHY THIS SCRIPT EXISTS. An ACA managed environment's `internal-only` setting is IMMUTABLE --
    `az containerapp env create` has `--internal-only`, `az containerapp env update` has no such
    option. Four environments were built internal-only and CANNOT be opened; the only fix is to
    delete the apps, the jobs and the environment, and recreate. `Setup-PimContainers.ps1` detects
    the mismatch and says exactly that, then deliberately refuses to do it -- deleting somebody's
    environment is not a thing an idempotent installer should do behind your back. So the deletion
    had no owner, and the rebuild was done by hand or not at all.

    🔒 THE ORDERING IS THE WHOLE SAFETY PROPERTY, and it is why this is a script rather than a
    runbook paragraph. The ENVIRONMENT's flag is immutable, but the APP's ingress is not
    (`az containerapp ingress update --type internal|external`). So:

        env created EXTERNAL-capable  ->  Manager recreated with ingress INTERNAL
        ->  Easy Auth attached to the NEW FQDN  ->  only THEN ingress flipped to external

    There is never a moment when a privileged-access GUI is reachable from the internet without
    authentication. Doing it in the obvious order -- recreate external, add auth after -- leaves
    exactly that window open, and the window is unattended.

    🪤 MEASURED 2026-09-11: EFIF and RIDE had NO Easy Auth at all (`az containerapp auth show`
    returned `{}`). Their internal-only environment WAS their access control. A rebuild that only
    changed the exposure would have published the Manager with nothing in front of it -- failing
    closed to Reader, which still READS every assignment and admin row. That is why -SkipEasyAuth
    is a switch you have to type, and why this script refuses to expose an app it cannot prove is
    protected.

    🔑 IT REBUILDS FROM A LIVE CAPTURE, NOT FROM INSTALLER PARAMETERS. This is a rebuild of a
    working environment, not a fresh install: the captured definition is known-good and currently
    serving. Re-deriving ~30 installer inputs would risk silent drift in precisely the config that
    works today -- and those inputs would have to be read off this same environment anyway. The
    capture is taken fresh every run (never reused) and the result is DIFFED back against it, so
    "recreated faithfully" is proven rather than asserted.

.PARAMETER Apply
    Actually do it. Without this the script prints the plan, writes the capture, and stops.

.PARAMETER SkipEasyAuth
    Leave the Manager on INTERNAL ingress and do not attach Easy Auth. Use when you intend to
    attach auth yourself. The Manager is NOT exposed in this mode -- that is the point.

.EXAMPLE
    # 1. plan (writes a capture, changes nothing)
    ./Rebuild-PimEnvExternal.ps1 -Tag wa678 -SubscriptionId <sub> -ResourceGroup rg-automateit-wa678

    # 2. do it
    ./Rebuild-PimEnvExternal.ps1 -Tag wa678 -SubscriptionId <sub> -ResourceGroup rg-automateit-wa678 `
        -EasyAuthTenantId <tenant> -Apply
#>
[CmdletBinding()]
param(
    # Names the capture files. For the estate this is the naming token (wa678 / rj466); for a
    # customer it is any short label.
    [Parameter(Mandatory)][string]$Tag,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$EnvName    = 'cae-pim',
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$CaptureDir,
    # Required unless -SkipEasyAuth: the tenant whose Entra signs users in to the Manager.
    [string]$EasyAuthTenantId,
    # 100.41: no az any more -- accepted so existing callers keep working, and ignored.
    [string]$AzureConfigDir,
    [switch]$SkipEasyAuth,
    [switch]$KeepOldPrivateDnsZone,
    # 🔴 RESUME AFTER A PARTIAL RUN. The capture is taken from the LIVE environment, so once the
    # apps and jobs are deleted there is nothing left to capture -- a naive re-run would capture
    # NOTHING and have nothing to restore. That is unrecoverable in production, and it is exactly
    # what the first live run walked into (delete succeeded, create was rejected, run stopped).
    # With this, the run re-uses the capture already on disk and skips straight to the recreate.
    # 🔑 THE STABLE NAME, and the reason to set it DURING the rebuild rather than after.
    # The ACA domain is regenerated every time the environment is recreated
    # (ashyplant-… -> jollyplant-… -> …), so anything pinned to it is disposable. A custom domain
    # is the one address that survives.
    # 🔴 AND EASY AUTH IS WHY THE TIMING MATTERS: the reply URL must match the URL people actually
    # visit. Adding the custom domain afterwards means changing the sign-in configuration a SECOND
    # time -- on the control that decides who can get in. Supplied here, auth is configured once,
    # against the final name.
    # Requires two DNS records, which only you can create; the script prints them exactly and waits.
    [string]$CustomDomain,
    # Set once the CNAME + asuid TXT records are live, to skip the interactive wait.
    [switch]$CustomDomainDnsReady,
    [switch]$ResumeFromCapture,
    # How long to wait for the async environment delete before giving up. ACA with VNet integration
    # routinely takes 15-30 minutes because it must release the subnet delegation.
    [int]$DeleteTimeoutSeconds = 2700,

    # ---- IDENTITY REPAIR (see step 0c) -----------------------------------------------------------
    # 🔴 Recreating a container app mints a NEW system-assigned managed identity, and everything
    # keyed to the old principal stops matching: the SQL contained users (whose SID is the old MI's
    # appId) and every Azure role assignment. Neither is configuration, so the config diff that
    # guards this script cannot see either one. Give it a SQL admin credential and it repairs the
    # users itself; without one it can still repair the ROLE assignments, and it says clearly that
    # the SQL half is owed.
    [string]$SqlServer,
    [string]$SqlDatabase = 'PimPlatform',
    # Any principal that is db_owner in $SqlDatabase -- the engine SPN qualifies and is usually the
    # easiest to reach (its id + secret live in the environment's own key vault).
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    # Opt OUT of the repair. Only sane when nothing has a system-assigned identity, which the
    # capture will tell you.
    [switch]$SkipIdentityRepair,

    # SEC-44 -- forwarded to Set-PimManagerEasyAuth: WHO may sign in (named principals, or every member
    # account and never a guest). Required unless the Manager's application is already assignment-required.
    [string[]]$EasyAuthAllowedPrincipals = @(),
    [switch]$EasyAuthAllowAllTenantUsers,

    # ---- §92 NET-2: THE OTHER DIRECTION (external -> internal) ----------------------------------------
    # Same capture / delete / recreate / restore / diff / identity repair, with the environment recreated
    # --internal-only TRUE. Rebuild-PimEnvInternal.ps1 calls this with -ToExposure Internal. The Manager is
    # then reachable only from the VNet and its peers, so the private DNS zone for the NEW default domain is
    # created (apex + wildcard A -> the environment's static IP) and linked to the spoke VNet and -HubVnetId.
    [ValidateSet('External', 'Internal')][string]$ToExposure = 'External',
    [string[]]$HubVnetId = @(),
    [string]$PrivateDnsResourceGroup,
    # §92 NET-3: turn the registry's public network access OFF (Premium only). REFUSED when the registry has
    # no private endpoint: the environment pulls images and the in-cloud updater builds over it, so locking
    # it without one stops every update. Never done implicitly.
    [switch]$LockRegistry,
    # §92 NET-1: re-grant the new identities' Graph app roles + the tick-start rights (Initialize-PimHostingAccess)
    # after the identity repair. Needs the tenant and a certificate identity that may write app-role assignments.
    [string]$HostingAccessTenantId,
    [string]$HostingAccessClientId,
    [string]$HostingAccessCertThumbprint,

    [switch]$Apply
)
$wantInternal = ($ToExposure -eq 'Internal')
$fromWord = $(if ($wantInternal) { 'EXTERNAL' } else { 'INTERNAL-ONLY' }); $toWord = $(if ($wantInternal) { 'INTERNAL-ONLY' } else { 'EXTERNAL' })

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent $here

# 100.41 (framework 12.17 NO-AZ): every Azure call is ARM / Graph REST through PIM-Rest's one token client
# (engine/_shared/PIM-ArmSetup.ps1), addressed BY subscription -- nothing touches a machine-wide default context, so there
# is no az profile to isolate any more (-AzureConfigDir is accepted and ignored). The session: a calling script's, else the
# Invardia Support app's for this tenant, else the person signed in.
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId) }
if ("$AzureConfigDir".Trim()) { Write-Host "  ! -AzureConfigDir '$AzureConfigDir' is ignored: this rebuild uses no az CLI (ARM / Graph REST)." -ForegroundColor Yellow }
if (-not "$CaptureDir".Trim()) {
    $CaptureDir = Join-Path ([IO.Path]::GetTempPath()) "pim-rebuild-$Tag-$(Get-Date -Format yyyyMMdd-HHmmss)"
}
$null = New-Item -ItemType Directory -Force -Path $CaptureDir

$script:fail = 0
function Say($m, $c='Gray'){ Write-Host "  $m" -ForegroundColor $c }
function Step($m){ Write-Host "`n==> $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "  ! $m" -ForegroundColor Yellow }
function Bad($m){ Write-Host "  X $m" -ForegroundColor Red; $script:fail++ }
function RgList([string]$Type, [string]$Kind, [string]$Child) {
    # az <type> list -g RG: every resource of one type in the resource group ($null-free; @() when unreadable).
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/$Type" + $(if ("$Child".Trim()) { "/$Child" } else { '' })
    @(Invoke-PimSetupArm -Path $path -ApiVersion (Get-PimSetupApiVersion $Kind) -All -ErrorAsNull) | Where-Object { $null -ne $_ }
}
function Get-RoleAssignmentsOf([string]$PrincipalId) {
    # az role assignment list --assignee P --all: every assignment of P in the subscription (any scope), as @{ role; scope }.
    $f = [uri]::EscapeDataString("principalId eq '$PrincipalId'")
    @(Invoke-PimSetupArm -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" -ApiVersion (Get-PimSetupApiVersion authorization) -All -ErrorAsNull) |
        Where-Object { $_ -and "$($_.properties.principalId)" -eq $PrincipalId } |
        ForEach-Object { @{ role = (Get-PimArmRoleName -RoleDefinitionId "$($_.properties.roleDefinitionId)"); scope = "$($_.properties.scope)" } }
}
function SaveCap($name, $obj) {
    $p = Join-Path $CaptureDir "$Tag-$name.json"
    $obj | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $p -Encoding UTF8
    return $p
}
function DropNulls($x) {
    # 🪤 @($null) IS AN ARRAY OF ONE NULL, NOT AN EMPTY ARRAY -- so `.Count` is 1 and every
    # "if (X.Count)" guard fires on ABSENCE. MEASURED live 2026-09-11: job 'ca-pim-update' has no
    # secrets at all, LoadCap returned $null, @($null) counted 1, and the restore handed ARM a
    # secret named '' -- "(ContainerAppSecretInvalid) ... secret(s) with name(s) '' are invalid".
    # Both LoadCap (file absent) and AzJson (empty or failed az) return $null, so EVERY @(...)
    # wrapped around either of them needs this.
    @($x) | Where-Object { $null -ne $_ }
}
function LoadCap($name) {
    $p = Join-Path $CaptureDir "$Tag-$name.json"
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
}
# =================================================================================================
# 🔴 SEC-35 -- SECRET VALUES NEVER REACH THE DISK IN CLEAR TEXT, AND WHAT IS WRITTEN IS SHREDDED.
# This used to save `secret list --show-values` as plain JSON in the capture directory (%TEMP% by
# default, its path printed at the end) and embed the same values in the restore YAML -- and nothing
# ever removed either: the Easy Auth client secret and any engine secret sat in a temp folder for good.
#   * the secret CAPTURE is stored DPAPI-protected (ConvertFrom-SecureString: only this Windows user on
#     this machine can read it back) -- still enough to RESUME after the delete, which is the only
#     reason the values are kept at all;
#   * a restore document (which must carry the values for `--yaml`) exists only for the one az call
#     that consumes it, and is overwritten then deleted in a finally;
#   * a COMPLETED rebuild shreds the protected captures too -- nothing is left to resume.
# A capture written by the old version (plain text) is still read for a resume, and shredded with the rest.
# =================================================================================================
$script:SecretFilesToShred = New-Object System.Collections.Generic.List[string]
function Remove-PimSecretFile([string]$Path) {
    if (-not "$Path".Trim() -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -gt 0) {
            $junk = New-Object byte[] $len
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($junk) } finally { $rng.Dispose() }
            [System.IO.File]::WriteAllBytes($Path, $junk)
        }
    } catch { }
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}
# DPAPI (CurrentUser) straight from .NET: the same protection ConvertFrom-SecureString gives, without
# depending on the Security module loading (it does not, in a Windows PowerShell spawned from pwsh 7).
function Protect-PimCapValue([string]$Value) {
    if (-not "$Value") { return '' }
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
    $enc = [System.Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Value), $null,
               [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Convert]::ToBase64String($enc)
}
function Unprotect-PimCapValue([string]$Protected) {
    if (-not "$Protected".Trim()) { return '' }
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch { }
    $dec = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Protected), $null,
               [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    return [Text.Encoding]::UTF8.GetString($dec)
}
function SaveSecretCap($name, $secrets) {
    $p = Join-Path $CaptureDir "$Tag-$name.protected.json"
    $rows = @(@($secrets) | Where-Object { $null -ne $_ } | ForEach-Object {
        [ordered]@{ name = "$($_.name)"; protectedValue = (Protect-PimCapValue "$($_.value)") } })
    ConvertTo-Json -InputObject @($rows) -Depth 5 | Set-Content -LiteralPath $p -Encoding UTF8
    [void]$script:SecretFilesToShred.Add($p)
    return $p
}
function LoadSecretCap($name) {
    $p = Join-Path $CaptureDir "$Tag-$name.protected.json"
    if (Test-Path -LiteralPath $p) {
        [void]$script:SecretFilesToShred.Add($p)
        # PS 5.1: ConvertFrom-Json emits a JSON array as ONE object -- assign first, then enumerate.
        $parsed = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        $rows = @($parsed)
        return @($rows | Where-Object { $null -ne $_ -and "$($_.name)" } | ForEach-Object {
            [pscustomobject]@{ name = "$($_.name)"; value = (Unprotect-PimCapValue "$($_.protectedValue)") } })
    }
    $legacy = Join-Path $CaptureDir "$Tag-$name.json"
    if (Test-Path -LiteralPath $legacy) {
        Warn "capture '$legacy' holds secret values in CLEAR TEXT (written by an older version) -- used for this resume, and shredded when the rebuild completes."
        [void]$script:SecretFilesToShred.Add($legacy)
        return (Get-Content -LiteralPath $legacy -Raw | ConvertFrom-Json)
    }
    return $null
}
function Strip($doc, [string[]]$top, [string[]]$props) {
    foreach ($p in $top)   { $doc.PSObject.Properties.Remove($p) }
    foreach ($p in $props) { $doc.properties.PSObject.Properties.Remove($p) }
    # 🔴 THE IDENTITY BLOCK CARRIES SERVER-ASSIGNED, READ-ONLY IDS, and ARM rejects them on create:
    #   (InvalidResourceIdentityPrincipalId) The principalId '<guid>' on the resource's Identity
    #   property must be null or empty for 'SystemAssigned, UserAssigned' identity type.
    # MEASURED on the first live restore 2026-09-11 -- the app AND both jobs all failed on it.
    # principalId/tenantId describe the identity Azure MINTED last time; only the user-assigned
    # ASSIGNMENTS (the resource ids) are input. The values inside userAssignedIdentities are
    # read-only too, so they are blanked to empty objects -- the KEY is what assigns the identity.
    if ($doc.PSObject.Properties['identity'] -and $doc.identity) {
        foreach ($p in 'principalId','tenantId') { $doc.identity.PSObject.Properties.Remove($p) }
        if ($doc.identity.PSObject.Properties['userAssignedIdentities'] -and $doc.identity.userAssignedIdentities) {
            $uai = [ordered]@{}
            foreach ($k in @($doc.identity.userAssignedIdentities.PSObject.Properties.Name)) { $uai[$k] = @{} }
            $doc.identity | Add-Member -NotePropertyName 'userAssignedIdentities' -NotePropertyValue $uai -Force
        }
    }
    return $doc
}
# =================================================================================================
# SQL -- only for the identity repair (step 0c / 9b). Kept tiny and dependency-free on purpose:
# this script must run on a bare host, and pulling in SqlServer/Az modules would be a new
# prerequisite on the one script you reach for when an environment is already broken.
# =================================================================================================
function ConvertTo-SidHex([string]$AppId) {
    # 🔑 THE SID OF A CONTAINED USER IS THE APP ID, NOT THE OBJECT ID, as a little-endian GUID byte
    # string. Getting this wrong creates a user that exists, looks right, and never authenticates.
    # 🔒 REFUSES an empty/unparseable appId rather than returning '0x'. A blank here would create a
    # user with an empty SID -- one that exists, reports success, and can never log in.
    if (-not "$AppId".Trim()) { throw 'ConvertTo-SidHex: empty appId -- refusing to build an empty SID.' }
    '0x' + ((([guid]$AppId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-PimIdentityRepairPlan {
    <#
      PURE. Decides WHAT the repair must do; performs none of it. Extracted so the decision is
      testable offline against a real capture -- the execution below needs live Azure and SQL, and
      "it looked right when I read it" is what let the original defect ship.

      Before   : @(@{ name; kind; principalId; appId; roles=@(@{role;scope}) })   -- pre-delete
      Now      : @(@{ name; principalId; appId })                                 -- post-restore
      SqlUsers : @(@{ name; sid; roles })                                         -- pre-delete
    #>
    [CmdletBinding()] param($Before, $Now, $SqlUsers)
    $plan = @{ roleGrants = @(); sqlRemaps = @(); unchanged = @(); problems = @() }
    foreach ($b in @($Before)) {
        $n = @($Now) | Where-Object { $_.name -eq $b.name } | Select-Object -First 1
        if (-not $n) { $plan.problems += "'$($b.name)' had a system-assigned identity before and is absent now"; continue }
        if (-not "$($n.principalId)".Trim()) { $plan.problems += "'$($b.name)' has no system-assigned identity after the rebuild"; continue }
        # A blank appId must NEVER become a SID. Treat it as a problem, not as a value.
        if (-not "$($n.appId)".Trim()) { $plan.problems += "could not resolve an appId for '$($b.name)' -- refusing to guess a SID"; continue }
        if ("$($n.principalId)" -eq "$($b.principalId)") { $plan.unchanged += $b.name; continue }

        foreach ($ra in @($b.roles)) { $plan.roleGrants += @{ name=$b.name; principalId=$n.principalId; role=$ra.role; scope=$ra.scope } }

        $u = @($SqlUsers) | Where-Object { $_.name -eq $b.name } | Select-Object -First 1
        if ($u) {
            $want = ConvertTo-SidHex $n.appId
            if ("$($u.sid)" -ieq $want) { $plan.unchanged += "$($b.name) (sql already current)" }
            else { $plan.sqlRemaps += @{ name=$b.name; oldSid="$($u.sid)"; newSid=$want
                                         roles=@("$($u.roles)".Split(',') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() }) } }
        }
    }
    return $plan
}
function Get-SqlConn {
    # Returns an OPEN connection, or $null when no credential was supplied (the caller then says
    # what is owed rather than pretending the repair happened).
    if (-not "$SqlServer".Trim() -or -not "$SqlAdminClientId".Trim()) { return $null }
    if (-not "$SqlAdminClientSecret".Trim() -and -not "$SqlAdminCertThumbprint".Trim()) { return $null }
    # The tenant of THIS run's REST session (pinned to the subscription's tenant by Connect-PimSetupRest).
    $tid = $(if ("$EasyAuthTenantId".Trim()) { $EasyAuthTenantId } else { "$($global:PIM_TenantId)".Trim() })
    # PIM-Rest's token client with the SQL admin identity named EXPLICITLY -- the run's own session (its globals) is left
    # alone, so the ARM calls after this still run as the identity that started the rebuild.
    $sqlTok = @{ Resource = 'https://database.windows.net/'; TenantId = $tid; ClientId = $SqlAdminClientId }
    if ("$SqlAdminClientSecret".Trim()) { $sqlTok['ClientSecret'] = $SqlAdminClientSecret } else { $sqlTok['CertThumbprint'] = $SqlAdminCertThumbprint }
    $tok = Get-PimRestToken @sqlTok
    if (-not "$tok".Trim()) { throw 'could not obtain a SQL access token for the identity repair.' }
    $c = New-Object System.Data.SqlClient.SqlConnection "Server=tcp:$SqlServer,1433;Database=$SqlDatabase;Encrypt=True;Connection Timeout=30;"
    $c.AccessToken = $tok
    $c.Open()
    return $c
}
function SqlRows($conn, [string]$sql) {
    $k = $conn.CreateCommand(); $k.CommandText = $sql
    $r = $k.ExecuteReader(); $out = @()
    while ($r.Read()) {
        $row = @{}
        for ($i = 0; $i -lt $r.FieldCount; $i++) { $row[$r.GetName($i)] = $r.GetValue($i) }
        $out += ,$row
    }
    $r.Close(); return $out
}
function SqlExec($conn, [string]$sql) { $k = $conn.CreateCommand(); $k.CommandText = $sql; [void]$k.ExecuteNonQuery() }

function Invoke-Checked {
    # 🔴 A CREATE THAT FAILED MUST NOT PRINT "restored".
    # The first live restore printed "restored (ingress INTERNAL, 1 secret(s))" for an app that
    # ARM had just rejected, because nothing read az's exit code -- so three consecutive failures
    # were reported as three successes, and only the verify step (by luck, indexing a null) stopped
    # the run. That is the same unverified-write defect this repo keeps finding; here it would have
    # ended with an empty environment reported as rebuilt. (100.41: a REST refusal throws; it is
    # re-thrown here with WHAT failed.)
    param([string]$What, [scriptblock]$Do)
    try { [void](& $Do) } catch { throw "$What FAILED ($($_.Exception.Message)) -- refusing to continue." }
}

function Get-PimRegistryLockDecision {
    <#
      PURE (§92 NET-3). May the registry's public network access be turned OFF? Only Premium has the switch, and only a
      registry WITH a private endpoint keeps working once it is off: the environment pulls images and the in-cloud
      updater builds over it. Returns @{ lock; reason }.
    #>
    param([string]$Sku, [string]$PublicNetworkAccess, [int]$PrivateEndpointCount = 0, [switch]$Requested)
    if ("$PublicNetworkAccess" -eq 'Disabled') { return @{ lock = $false; reason = 'public network access is already OFF' } }
    if ("$Sku" -ne 'Premium') { return @{ lock = $false; reason = "the registry is $Sku -- only Premium can turn public access off (Basic/Standard have no network controls at all)" } }
    if ($PrivateEndpointCount -lt 1) { return @{ lock = $false; reason = 'the registry has NO private endpoint -- turning public access off would stop every image pull and every update; add a private endpoint first' } }
    if (-not $Requested) { return @{ lock = $false; reason = 'it could be turned off (Premium, private endpoint present) -- pass -LockRegistry to do it' } }
    return @{ lock = $true; reason = 'Premium with a private endpoint -- public network access is turned OFF' }
}
function Get-PimInternalSwitchNotes {
    # §92 NET-3: what an internal environment still needs that the environment rebuild itself does not change.
    param([switch]$LockRegistry)
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(RgList 'Microsoft.ContainerRegistry/registries' acr)) {
        $pe = @($r.properties.privateEndpointConnections | Where-Object { $_ }).Count
        $d = Get-PimRegistryLockDecision -Sku "$($r.sku.name)" -PublicNetworkAccess "$($r.properties.publicNetworkAccess)" -PrivateEndpointCount $pe -Requested:$LockRegistry
        $notes.Add("registry $($r.name): $($d.reason)") | Out-Null
    }
    foreach ($s in @(RgList 'Microsoft.Sql/servers' sql)) {
        $pe = @($s.properties.privateEndpointConnections | Where-Object { $_ }).Count
        $notes.Add("sql $($s.name): " + $(if ($pe) { "private endpoint present ($pe)" } else { 'NO private endpoint -- the store is still reached over its public endpoint (VNet rule); add one with New-PimHostingPrerequisites -SqlPrivateEndpoint for a fully private store' })) | Out-Null
    }
    return @($notes)
}

Write-Host "=== Rebuild PIM environment as $toWord -- $Tag / $EnvName ===" -ForegroundColor Cyan
Say "subscription : $SubscriptionId"
Say "resource grp : $ResourceGroup"
Say "Azure        : ARM / Graph REST ($($global:PIM_SetupRestMode) session, tenant $($global:PIM_TenantId))"
Say "capture dir  : $CaptureDir"
Say ("mode         : " + $(if ($Apply) { 'APPLY' } else { 'PLAN (nothing will change)' })) `
    $(if ($Apply) { 'Yellow' } else { 'Green' })

# =================================================================================================
# 0. CAPTURE -- fresh, every run. Never reuse an older capture: the environment has been updated
#    since, and a rebuild from stale config silently reverts whatever changed.
# =================================================================================================
if ($ResumeFromCapture) {
    # 🔒 RESUME: trust the capture on disk, because the live environment no longer has the app or
    # jobs to capture. Validate that it is actually complete before relying on it -- resuming from a
    # half-written capture would restore a half-built environment and call it done.
    Step "0. RESUME from the existing capture in $CaptureDir"
    $envCap = LoadCap 'env'
    $appCap = LoadCap "app-$ManagerApp-full"
    $appSec = @(DropNulls (LoadSecretCap "app-$ManagerApp-secrets"))
    $authCap = LoadCap "app-$ManagerApp-auth"
    $jobsCap = @(DropNulls (LoadCap 'jobs'))
    if (-not $envCap -or -not $appCap) { throw "the capture in '$CaptureDir' is missing the environment or the Manager -- cannot resume from it." }
    foreach ($j in $jobsCap) {
        if (-not (LoadCap "job-$($j.name)-full")) { throw "the capture is missing job '$($j.name)' -- cannot resume from it." }
    }
    $hadEasyAuth = [bool]($authCap.identityProviders.azureActiveDirectory.registration.clientId)
    Say "captured manager : $ManagerApp  image=$($appCap.properties.template.containers[0].image)" 'Green'
    Say "captured secrets : $(if ($appSec.Count) { (@($appSec)|ForEach-Object{$_.name}) -join ', ' } else { '(none)' })"
    Say "captured jobs    : $(if ($jobsCap.Count) { (@($jobsCap)|ForEach-Object{$_.name}) -join ', ' } else { '(none)' })"
    foreach ($s in @($appSec)) { if (-not $s.value) { throw "captured secret '$($s.name)' has NO VALUE -- restoring would produce a broken app." } }
} else {

Step '0. capture the live environment (fresh -- an older capture is never reused)'
Say "direction    : $fromWord -> $toWord" 'Cyan'
$envCap = @(RgList 'Microsoft.App/managedEnvironments' aca) | Where-Object { $_.name -eq $EnvName }
if (-not $envCap) { throw "environment '$EnvName' not found in $ResourceGroup. If a previous run already deleted it, re-run with -CaptureDir <that run's dir> -ResumeFromCapture." }
$envCap = @($envCap)[0]
[void](SaveCap 'env' $envCap)

$isInternal = "$($envCap.properties.vnetConfiguration.internal)"
$subnetId   = $envCap.properties.vnetConfiguration.infrastructureSubnetId
$location   = $envCap.location
$oldDomain  = $envCap.properties.defaultDomain
$lawCid     = $envCap.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId
Say "internal-only: $isInternal   domain=$oldDomain"
Say "location     : $location"
Say "subnet       : $subnetId"

# 🔴 THIS IS A ONE-TIME MIGRATION, NOT A DEPLOY STEP (operator: "we cannot recreate env at every
# build"). It exists solely because `internal-only` is immutable, so the ONLY way to change it is to
# delete the environment. An environment that is already external has nothing to migrate, and
# recreating it would destroy a working environment for no reason -- and take the ~30 minute delete
# with it. So this REFUSES, unconditionally, and says what to use instead.
# ⇒ It is therefore safe to leave in a runbook: run it twice and the second run is a no-op.
# 🔒 Routine deploys go through Setup-PimContainers / Update-PimContainers, which never delete an
#    environment -- Setup-PimContainers detects this same mismatch and deliberately refuses to act
#    on it, which is why this script exists as a separate, explicit, one-time tool.
if (($wantInternal -and $isInternal -eq 'True') -or (-not $wantInternal -and $isInternal -ne 'True')) {
    Warn "environment '$EnvName' is ALREADY $toWord (internal=$isInternal). NOTHING TO REBUILD -- stopping."
    Warn "This script is a ONE-TIME migration for an environment built $fromWord. It is not a deploy step."
    Warn "To change only who can reach the Manager, use the APP's ingress (reversible, no downtime): '$ManagerApp' ingress external|internal."
    Warn 'To deploy code, use Update-PimContainers.ps1 -- it never deletes an environment.'
    return
}
if (-not $subnetId) { throw 'the environment has no infrastructure subnet -- refusing to recreate without it.' }
# 🔴 BUG-37: hand ACA the SAME workspace. A create with no workspace GENERATES one and writes every
# log there, leaving the real workspace empty and billed -- and anyone reading logs looking at the
# wrong place. Resolve the name now, while the environment still exists to be asked.
if (-not $lawCid) { throw 'the environment reports no Log Analytics workspace -- refusing to recreate without it. The container logs would be lost with nowhere to go.' }
$lawName = "$(@(Get-PimArmLogAnalyticsList -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup | Where-Object { "$($_.properties.customerId)" -eq "$lawCid" } | ForEach-Object { "$($_.name)" }) | Select-Object -First 1)"
if (-not "$lawName".Trim()) { throw "no workspace with customerId $lawCid in $ResourceGroup -- refusing to recreate the environment without its log destination." }
Say "log analytics: $lawName ($lawCid)"

$appCap = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
if (-not $appCap) { throw "Manager app '$ManagerApp' not found in $ResourceGroup." }
[void](SaveCap "app-$ManagerApp-full" $appCap)
$appSec = @(DropNulls (Get-PimArmAcaAppSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp))   # throws when unreadable: a capture without values cannot restore
[void](SaveSecretCap "app-$ManagerApp-secrets" $appSec)
# az's `auth show` shape (the properties of authConfigs/current), so a resume from an older capture reads the same way.
$authCap = (Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull).properties
[void](SaveCap "app-$ManagerApp-auth" $authCap)
$hadEasyAuth = [bool]($authCap.identityProviders.azureActiveDirectory.registration.clientId)
Say "manager      : $ManagerApp  image=$($appCap.properties.template.containers[0].image)"
Say "  secrets    : $(if ($appSec.Count) { (@($appSec)|ForEach-Object{$_.name}) -join ', ' } else { '(none)' })"
Say ("  easy auth  : " + $(if ($hadEasyAuth) { "already configured ($($authCap.identityProviders.azureActiveDirectory.registration.clientId))" } else { 'NONE -- the internal-only env IS the access control today' })) `
    $(if ($hadEasyAuth) { 'Gray' } else { 'Yellow' })

$jobsCap = @(DropNulls (Get-PimArmAcaJobList -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ErrorAsNull))
[void](SaveCap 'jobs' $jobsCap)
foreach ($j in $jobsCap) {
    [void](SaveCap "job-$($j.name)-full"    (Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $j.name -ErrorAsNull))
    [void](SaveSecretCap "job-$($j.name)-secrets" @(Get-PimArmAcaJobSecrets -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $j.name))
}
Say "jobs         : $(if ($jobsCap.Count) { (@($jobsCap)|ForEach-Object{$_.name}) -join ', ' } else { '(none)' })"

# 🔒 The keep-list, recorded so a mistaken deletion of any of it is instantly visible as a diff.
[void](SaveCap 'keep-identities' @(RgList 'Microsoft.ManagedIdentity/userAssignedIdentities' msi))
[void](SaveCap 'keep-acr'        @(RgList 'Microsoft.ContainerRegistry/registries' acr))
[void](SaveCap 'keep-sql'        @(RgList 'Microsoft.Sql/servers' sql))
[void](SaveCap 'keep-vnet'       @(RgList 'Microsoft.Network/virtualNetworks' network))
[void](SaveCap 'keep-law'        @(RgList 'Microsoft.OperationalInsights/workspaces' logAnalytics))
[void](SaveCap 'keep-kv'         @(RgList 'Microsoft.KeyVault/vaults' keyVault))
$dnsZones = @(RgList 'Microsoft.Network/privateDnsZones' privateDns)
[void](SaveCap 'private-dns' $dnsZones)

}   # end of the fresh-capture branch

# Derived the same way whichever branch ran, so a resumed run behaves identically from here.
$subnetId  = $envCap.properties.vnetConfiguration.infrastructureSubnetId
$location  = $envCap.location
$oldDomain = $envCap.properties.defaultDomain
$lawCid    = $envCap.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId
$lawName   = "$(@(Get-PimArmLogAnalyticsList -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup | Where-Object { "$($_.properties.customerId)" -eq "$lawCid" } | ForEach-Object { "$($_.name)" }) | Select-Object -First 1)"
if (-not "$lawName".Trim()) { throw "no workspace with customerId $lawCid in $ResourceGroup -- refusing to recreate the environment without its log destination." }
$dnsZones  = @(RgList 'Microsoft.Network/privateDnsZones' privateDns)
$staleZone = @($dnsZones | Where-Object { $_.name -eq $oldDomain }) | Select-Object -First 1

# 🔴 THE KEEP-LIST IS ENFORCED, NOT DOCUMENTED (operator: "we cannot delete data like sql").
# Everything that HOLDS DATA is recorded here BEFORE anything is deleted, and re-checked after the
# rebuild. A comment saying "we never touch SQL" is worth nothing on a sensitive environment; a
# list that is compared afterwards is evidence. If any of it is missing at the end, the run says so
# loudly rather than reporting a successful rebuild over a data loss.
function Get-PimKeepList {
    # Every DATA-bearing resource in the resource group, by name (the same list before and after the rebuild).
    $k = [ordered]@{
        'sql server'    = @(RgList 'Microsoft.Sql/servers' sql                                | ForEach-Object { $_.name }) | Sort-Object
        'sql database'  = @()
        'acr'           = @(RgList 'Microsoft.ContainerRegistry/registries' acr               | ForEach-Object { $_.name }) | Sort-Object
        'key vault'     = @(RgList 'Microsoft.KeyVault/vaults' keyVault                       | ForEach-Object { $_.name }) | Sort-Object
        'vnet'          = @(RgList 'Microsoft.Network/virtualNetworks' network                | ForEach-Object { $_.name }) | Sort-Object
        'log analytics' = @(RgList 'Microsoft.OperationalInsights/workspaces' logAnalytics    | ForEach-Object { $_.name }) | Sort-Object
        'identity'      = @(RgList 'Microsoft.ManagedIdentity/userAssignedIdentities' msi     | ForEach-Object { $_.name }) | Sort-Object
        'storage'       = @(RgList 'Microsoft.Storage/storageAccounts' storage                | ForEach-Object { $_.name }) | Sort-Object
    }
    # Databases are the ones that actually hold the customer's data, so they are enumerated per server.
    foreach ($srv in $k['sql server']) {
        $k['sql database'] += @(RgList 'Microsoft.Sql/servers' sql "$srv/databases" | ForEach-Object { "$srv/$($_.name)" })
    }
    $k['sql database'] = @($k['sql database']) | Sort-Object
    return $k
}
$script:KeepBefore = Get-PimKeepList
Say 'KEEP (recorded now, re-verified after the rebuild -- NOT just a promise):' 'Green'
foreach ($k in $script:KeepBefore.Keys) {
    $v = @($script:KeepBefore[$k])
    Say ("  {0,-14} {1}" -f $k, $(if ($v.Count) { $v -join ', ' } else { '(none)' })) 'DarkGray'
}
if ($staleZone -and -not $wantInternal) {
    Warn "private DNS zone '$oldDomain' exists -- it will SHADOW the new public name for VNet clients."
}

# =================================================================================================
# 0c. IDENTITY-KEYED STATE -- the thing this script verified nothing about, and broke every time.
#
# 🔴 MEASURED ON EFIF 2026-09-11. The restore diffed image, cpu, replicas, port, registry, secrets
# and every env var, declared "restore matches the capture", exposed the app -- and the Manager then
# crash-looped on:
#     Login failed for user '<token-identified principal>'
# because a deleted-and-recreated container app gets a BRAND NEW system-assigned managed identity.
# Everything keyed to the OLD principal silently stops matching:
#   * the SQL CONTAINED USERS, whose SID is the old MI's appId
#   * every AZURE ROLE ASSIGNMENT, which names the old principalId
# Neither is configuration, so a config diff cannot see either one, and both fail LATER and
# ELSEWHERE -- the SQL one as a crash loop, the RBAC one as a silently degraded tenant cache.
# User-assigned identities do NOT have this problem: their principal survives, which is precisely
# why the AcrPull identity kept working while everything else did not.
#
# Recorded HERE, before the delete, because after it the old principal is unresolvable in Graph and
# its role assignments are already gone -- there is nothing left to read.
# =================================================================================================
Step '0c. record identity-keyed state (SQL users + role assignments) BEFORE the delete'
$script:IdentBefore = @()
$identTargets = @(@{ kind='app'; name=$ManagerApp }) + @($jobsCap | ForEach-Object { @{ kind='job'; name=$_.name } })
foreach ($t in $identTargets) {
    $show = if ($t.kind -eq 'app') { Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $t.name -ErrorAsNull }
            else                   { Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $t.name -ErrorAsNull }
    $pid2 = "$($show.identity.principalId)".Trim()
    if (-not $pid2) { Say "  $($t.name): no system-assigned identity -- nothing keyed to it" 'DarkGray'; continue }
    # The SID a contained SQL user is created from is the APP ID, not the object id. Resolve it now:
    # after the delete this principal no longer exists and the lookup returns nothing.
    $appIdOf = "$((Get-PimGraphServicePrincipal -Id $pid2 -Select 'appId' -ErrorAsNull).appId)".Trim()
    $ras = @(Get-RoleAssignmentsOf $pid2)
    $script:IdentBefore += @{ kind=$t.kind; name=$t.name; principalId=$pid2; appId=$appIdOf; roles=$ras }
    Say ("  {0,-16} principal={1} appId={2} roles={3}" -f $t.name, $pid2, $(if ($appIdOf) { $appIdOf } else { '?' }), $ras.Count)
}
# The SQL contained users, recorded WITH their role memberships. A user's SID cannot be altered in
# place, so the repair is drop + create -- and a drop that forgets the roles leaves a user that
# authenticates and can read nothing, which is harder to spot than one that cannot log in at all.
$script:SqlUsersBefore = @()
if (-not $SkipIdentityRepair -and $script:IdentBefore.Count) {
    $conn = $null
    try { $conn = Get-SqlConn } catch { Warn "could not reach SQL to record the contained users: $($_.Exception.Message)" }
    if ($conn) {
        try {
            $names = ($script:IdentBefore | ForEach-Object { "'" + ($_.name -replace "'","''") + "'" }) -join ','
            $script:SqlUsersBefore = @(SqlRows $conn @"
SELECT p.name AS name, CONVERT(varchar(100), p.sid, 1) AS sid,
       ISNULL(STUFF((SELECT ',' + r.name FROM sys.database_role_members m
              JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
              WHERE m.member_principal_id = p.principal_id FOR XML PATH('')),1,1,''),'') AS roles
FROM sys.database_principals p
WHERE p.type IN ('E','X') AND p.name IN ($names)
"@)
            foreach ($u in $script:SqlUsersBefore) { Say ("  sql user {0,-16} sid={1} roles={2}" -f $u.name, $u.sid, $u.roles) }
            if (-not $script:SqlUsersBefore.Count) { Say '  no SQL contained users match these apps -- nothing to remap' 'DarkGray' }
        } finally { $conn.Close() }
    }
}
$null = SaveCap 'identities-before' @{ identities = $script:IdentBefore; sqlUsers = $script:SqlUsersBefore }
if (-not $script:IdentBefore.Count) { Say '  nothing has a system-assigned identity -- no identity repair will be needed' 'Green' }
elseif ($SkipIdentityRepair) { Warn '-SkipIdentityRepair: SQL users and role assignments will NOT be repaired.' }
elseif (-not "$SqlServer".Trim() -or -not "$SqlAdminClientId".Trim()) {
    Warn 'NO SQL CREDENTIAL GIVEN -- the contained users CANNOT be remapped after the rebuild.'
    Warn 'This is exactly what crash-looped EFIF: the Manager came up, passed every config diff, and'
    Warn 'then died on "Login failed for user ''<token-identified principal>''" because its new MI had'
    Warn 'no user. Pass -SqlServer + -SqlAdminClientId + -SqlAdminClientSecret (any db_owner will do;'
    Warn 'the engine SPN in the environment''s own key vault is the usual one). Role assignments are'
    Warn 'still repaired without it.'
}

# ---- refuse early, not half-way -----------------------------------------------------------------
if ($wantInternal -and -not $SkipEasyAuth -and -not $hadEasyAuth -and -not "$EasyAuthTenantId".Trim()) {
    # going INTERNAL narrows who can reach it; auth stays the right default, but nothing is newly exposed -- so warn, not refuse
    Warn 'No Easy Auth on the Manager and no -EasyAuthTenantId: it will be reachable from the VNet and its peers WITHOUT sign-in. Pass -EasyAuthTenantId to attach it.'
    $SkipEasyAuth = $true
}
if (-not $wantInternal -and -not $SkipEasyAuth -and -not $hadEasyAuth -and -not "$EasyAuthTenantId".Trim()) {
    throw ("This environment has NO Easy Auth, so making it external would publish the Manager " +
           "unauthenticated. Pass -EasyAuthTenantId <tenant> so auth can be attached before it is " +
           "exposed, or -SkipEasyAuth to leave the Manager on INTERNAL ingress and attach auth yourself.")
}

if (-not $Apply) {
    Step 'PLAN ONLY -- nothing was changed'
    Say "would DELETE : $(@($jobsCap).Count) job(s), app '$ManagerApp', environment '$EnvName'"
    Say "would CREATE : '$EnvName' with --internal-only $(if ($wantInternal) { 'true' } else { 'false' }) (same subnet, same workspace)"
    Say "would RESTORE: '$ManagerApp' with ingress INTERNAL, then $(@($jobsCap).Count) job(s)"
    Say ("would THEN   : " + $(if ($SkipEasyAuth) { 'stop (Manager stays INTERNAL)' } else { 'attach Easy Auth, verify it, then flip ingress to external' + $(if ($wantInternal) { ' (inside an internal-only environment = the VNet and its peers only)' } else { '' }) }))
    if ($wantInternal) { Say ("would CREATE : private DNS zone for the NEW default domain -> the static IP, linked to the spoke VNet" + $(if (@($HubVnetId).Count) { " + $(@($HubVnetId).Count) hub VNet(s)" } else { ' (no -HubVnetId: peered clients will not resolve it)' })) }
    if ($wantInternal) { foreach ($n in @(Get-PimInternalSwitchNotes -LockRegistry:$LockRegistry)) { Say "NOTE         : $n" 'Yellow' } }
    if (-not $wantInternal -and $staleZone -and -not $KeepOldPrivateDnsZone) { Say "would DELETE : stale private DNS zone '$oldDomain'" }
    if (-not "$HostingAccessTenantId".Trim()) { Say 'NOTE         : no -HostingAccessTenantId -- the Graph app roles of the NEW identities are NOT re-granted; run Initialize-PimHostingAccess.ps1 afterwards' 'Yellow' }
    Say "capture written to $CaptureDir" 'Green'
    Say 'Re-run with -Apply to execute.' 'Yellow'
    return
}

# =================================================================================================
# 1-3. DELETE. Jobs first, then the app, then the environment (ACA refuses to drop an environment
#      that still has children, and deleting them explicitly makes the order auditable).
# =================================================================================================
# 🔴 A RESUME MUST NOT RE-DELETE WHAT THE FAILED RUN ALREADY REBUILT.
# MEASURED 2026-09-11: the first resume ran the delete phase unconditionally and destroyed the
# EXTERNAL environment the previous run had just created -- costing a second 15-30 minute delete
# cycle for nothing. "Resume" means continue, not start over; the delete phase is only correct
# while the environment is still the OLD internal-only one.
# 🔑 Decide from the LIVE state, not from the switch: if the environment is already external, the
# deletes are done and the run belongs at the restore step.
$envNow = Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
$envNowInternal = ($envNow -and "$($envNow.properties.vnetConfiguration.internal)" -eq 'True')
$skipDeletes = ($envNow -and ($envNowInternal -eq $wantInternal))
if ($skipDeletes) {
    Step "1-3. SKIPPED -- '$EnvName' is already $toWord, so the deletes are already done"
    Say 'resuming at the restore step.' 'Green'
} else {

Step '1. delete the jobs'
# A refused delete is not fatal here, as before: the async wait below is what decides (an environment that still has
# children, or is still there, is never created over).
foreach ($j in $jobsCap) {
    Say "deleting job $($j.name)"
    try { Remove-PimArmResource -ResourceId (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/jobs' $j.name) -Kind aca -Wait -TimeoutSeconds 600 } catch { Warn "job delete: $($_.Exception.Message)" }
}
Step "2. delete the app '$ManagerApp'"
try { Remove-PimArmResource -ResourceId (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/containerApps' $ManagerApp) -Kind aca -Wait -TimeoutSeconds 600 } catch { Warn "app delete: $($_.Exception.Message)" }
Step "3. delete the environment '$EnvName' (the immutable flag being changed)"
try { Remove-PimArmResource -ResourceId (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.App/managedEnvironments' $EnvName) -Kind aca } catch { Warn "environment delete: $($_.Exception.Message)" }
# 🔴 THE ENVIRONMENT DELETE RETURNS BEFORE THE DELETION COMPLETES. The environment sits in
# `ScheduledForDelete` for a long time -- with VNet integration it must release the subnet
# delegation first -- and a create issued in that window is REJECTED:
#     (ManagedEnvironmentScheduledForDelete) The environment 'x' is under deletion.
# MEASURED on the first live run 2026-09-11: delete returned, create failed ~instantly, and the
# rebuild stopped with the environment gone and nothing restored. The refusal was correct; the
# assumption that delete is synchronous was not. WAIT for it to actually disappear.
Step "3b. wait for '$EnvName' to actually be gone (delete is ASYNC)"
$waited = 0
while ($true) {
    $stillEnv = Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
    $still = ''
    if ($stillEnv) { $still = "$($stillEnv.properties.provisioningState)".Trim(); if (-not $still) { $still = 'present' } }
    if (-not "$still".Trim()) { Say "gone after ${waited}s" 'Green'; break }
    if ($waited -ge $DeleteTimeoutSeconds) {
        throw ("environment '$EnvName' is still '$still' after ${waited}s. It is NOT safe to create " +
               "over it -- Azure rejects a create while the old one is ScheduledForDelete. Wait for " +
               "the deletion to finish, then re-run with -CaptureDir '$CaptureDir' -ResumeFromCapture.")
    }
    if ($waited % 60 -eq 0) { Say "still '$still' (${waited}s elapsed)" 'DarkGray' }
    Start-Sleep -Seconds 15; $waited += 15
}

}   # end of the delete phase (skipped when the environment is already external)

# =================================================================================================
# 4. RECREATE the environment, EXTERNAL-capable.
# =================================================================================================
$internalFlag = $(if ($wantInternal) { 'true' } else { 'false' })
Step "4. create the environment with internal-only = $internalFlag"
$lawKey = Get-PimArmLogAnalyticsKey -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $lawName
if (-not "$lawKey".Trim()) { throw "could not read the shared key for workspace '$lawName' -- refusing to recreate the environment without its log destination." }
# 🔑 IDEMPOTENT ON RESUME. A resumed run may find the environment already recreated by the run
# that failed later on -- recreating it would delete the work and start the 15-30 minute wait
# again. Re-use it when it is already EXTERNAL; refuse if it somehow came back internal.
$existing = Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
$existingInternal = ($existing -and "$($existing.properties.vnetConfiguration.internal)" -eq 'True')
if ($existing -and ($existingInternal -eq $wantInternal)) {
    Say "environment '$EnvName' already exists and is $toWord -- reusing it" 'Green'
} else {
    if ($existing) { throw "environment '$EnvName' exists and is still $fromWord -- delete it before resuming." }
    # The same subnet, the same workspace, workload profiles (Consumption), internal = the target exposure.
    $envProps = @{
        vnetConfiguration    = @{ infrastructureSubnetId = $subnetId; internal = $wantInternal }
        workloadProfiles     = @(@{ name = 'Consumption'; workloadProfileType = 'Consumption' })
        appLogsConfiguration = @{ destination = 'log-analytics'; logAnalyticsConfiguration = @{ customerId = "$lawCid"; sharedKey = "$lawKey" } }
    }
    Invoke-Checked "create environment '$EnvName'" { Set-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -Properties $envProps -Create -Location $location -TimeoutSeconds $DeleteTimeoutSeconds }
}
$newEnv = Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
if (-not $newEnv) { throw 'the environment was not created.' }
# VERIFY, never assume -- this is the one property the whole exercise exists to change.
if ((("$($newEnv.properties.vnetConfiguration.internal)" -eq 'True')) -ne $wantInternal) {
    throw "the recreated environment is STILL $fromWord -- refusing to continue."
}
$newDomain = $newEnv.properties.defaultDomain
Say "new domain   : $newDomain" 'Green'
Say "static IP    : $($newEnv.properties.staticIp)" 'Green'
$newEnvId = $newEnv.id

# =================================================================================================
# 5. RESTORE the Manager -- ingress INTERNAL. No public exposure until auth is proven.
# =================================================================================================
Step "5. restore '$ManagerApp' with ingress INTERNAL"
$doc = $appCap | ConvertTo-Json -Depth 40 | ConvertFrom-Json
$doc = Strip $doc @('id','name','systemData','resourceGroup','type') `
        @('customDomainVerificationId','eventStreamEndpoint','latestReadyRevisionName','latestRevisionFqdn',
          'latestRevisionName','outboundIpAddresses','provisioningState','runningStatus','delegatedIdentities',
          'managedEnvironmentId')
$doc.properties.environmentId = $newEnvId
$doc.properties.configuration.ingress.external = $false
$doc.properties.configuration.ingress.PSObject.Properties.Remove('fqdn')
# `show` returns secret NAMES only; re-attach the captured VALUES or the app boots without them.
if ($appSec.Count) {
    $doc.properties.configuration.secrets = @($appSec | ForEach-Object { [ordered]@{ name = $_.name; value = $_.value } })
}
# 🔑 IDEMPOTENT ON RESUME, same reason as step 4: a run that failed at step 6 leaves a correctly
# restored app behind, and re-creating it would discard it for no gain. Skipping is safe ONLY
# because step 7 diffs whatever is live against the capture and refuses to expose a mismatch --
# so a reused app still has to prove itself.
if (Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull) {
    Say "'$ManagerApp' already exists -- reusing it (step 7 will diff it against the capture)" 'Green'
} else {
    # SEC-35: the document carries secret VALUES -- it goes straight into the ARM PUT and is never written to disk
    # (az's --yaml needed a file; REST does not).
    Invoke-Checked "create app '$ManagerApp'" { Set-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Resource $doc -Create }
    $doc = $null
    Say "restored (ingress INTERNAL, $($appSec.Count) secret(s))" 'Green'
}

Step '6. restore the jobs'
foreach ($j in $jobsCap) {
    $n = $j.name
    $jc = LoadCap "job-$n-full"; $js = @(DropNulls (LoadSecretCap "job-$n-secrets"))
    if (-not $jc) { Bad "no capture for job '$n' -- recreate it by hand"; continue }
    $jd = $jc | ConvertTo-Json -Depth 40 | ConvertFrom-Json
    $jd = Strip $jd @('id','name','systemData','resourceGroup','type') `
            @('provisioningState','runningState','outboundIpAddresses','eventStreamEndpoint')
    $jd.properties.environmentId = $newEnvId
    if ($js.Count) { $jd.properties.configuration.secrets = @($js | ForEach-Object { [ordered]@{ name = $_.name; value = $_.value } }) }
    if (Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull) {
        Say "job '$n' already exists -- reusing it (verified below)" 'Green'
    } else {
        # SEC-35: same rule as the app -- the document with the values goes into the PUT, never onto disk.
        Invoke-Checked "create job '$n'" { Set-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $n -Resource $jd -Create }
        $jd = $null
        Say "restored job $n$(if ($js.Count) { " (+$($js.Count) secret(s))" })" 'Green'
    }
}

# =================================================================================================
# 6b. VERIFY THE JOBS against their captures. Step 7 has always diffed the Manager, but the jobs
#     were taken on trust -- and the jobs are what actually RUN the engine and the self-update. A
#     tick job restored without AZURE_CLIENT_SECRET, or on the wrong image, fails silently at 03:00
#     rather than here. Same evidence-not-claim rule as step 7.
# =================================================================================================
Step '6b. verify the restored jobs against their captures'
foreach ($j in $jobsCap) {
    $n = $j.name
    $was = LoadCap "job-$n-full"
    $nowJ = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull
    if (-not $nowJ) { Bad "job '$n' does not exist after the restore"; continue }
    $wc = $was.properties.template.containers[0]; $nc = $nowJ.properties.template.containers[0]
    if ("$($wc.image)" -ne "$($nc.image)") { Bad "job '$n' image DIFFERS: was='$($wc.image)' now='$($nc.image)'" }
    if ("$($was.properties.configuration.triggerType)" -ne "$($nowJ.properties.configuration.triggerType)") {
        Bad "job '$n' triggerType DIFFERS: was='$($was.properties.configuration.triggerType)' now='$($nowJ.properties.configuration.triggerType)'"
    }
    if ("$($was.properties.configuration.scheduleTriggerConfig.cronExpression)" -ne "$($nowJ.properties.configuration.scheduleTriggerConfig.cronExpression)") {
        Bad "job '$n' cron DIFFERS: was='$($was.properties.configuration.scheduleTriggerConfig.cronExpression)' now='$($nowJ.properties.configuration.scheduleTriggerConfig.cronExpression)'"
    }
    $wasE = @{}; foreach ($e in @($wc.env)) { $wasE[$e.name] = "$($e.value)$($e.secretRef)" }
    $nowE = @{}; foreach ($e in @($nc.env)) { $nowE[$e.name] = "$($e.value)$($e.secretRef)" }
    foreach ($k in $wasE.Keys) {
        if (-not $nowE.ContainsKey($k)) { Bad "job '$n' env var MISSING: $k" }
        elseif ($wasE[$k] -ne $nowE[$k]) { Bad "job '$n' env var CHANGED: $k" }
    }
    # Secret NAMES only -- `show` never returns values, and comparing counts alone would pass a
    # job whose one secret came back under a different name (exactly the '' name seen live).
    $wasS = @(DropNulls $was.properties.configuration.secrets | ForEach-Object { "$($_.name)" }) | Sort-Object
    $nowS = @(DropNulls $nowJ.properties.configuration.secrets | ForEach-Object { "$($_.name)" }) | Sort-Object
    if (($wasS -join ',') -ne ($nowS -join ',')) { Bad "job '$n' secrets DIFFER: was='$($wasS -join ',')' now='$($nowS -join ',')'" }
    if (-not $script:fail) { Say "  job '$n' matches the capture ($($wasE.Count) env var(s), $($wasS.Count) secret(s))" }
}
if ($script:fail) { throw "the restored jobs do not match their captures ($script:fail difference(s)) -- stopping." }

# =================================================================================================
# 6c. IDENTITY REPAIR -- re-point everything that was keyed to the OLD system-assigned identities.
#
# Runs HERE: after the apps and jobs exist (so the new principals are readable) and BEFORE the
# Manager is exposed (step 9), because an app whose SQL user is missing crash-loops -- exposing it
# first only publishes a broken app faster.
# =================================================================================================
if (-not $SkipIdentityRepair -and $script:IdentBefore.Count) {
Step '6c. repair identity-keyed state (new system-assigned MIs)'

# Resolve the NEW principal + appId for each thing that had one before. OBSERVATION ONLY -- what to
# DO about it is Get-PimIdentityRepairPlan's decision, which is proven offline against the real EFIF
# numbers in tests/Test-PimRebuildIdentityRepair.ps1.
$identNow = @()
foreach ($b in $script:IdentBefore) {
    $show = if ($b.kind -eq 'app') { Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $b.name -ErrorAsNull }
            else                   { Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $b.name -ErrorAsNull }
    $newPid = "$($show.identity.principalId)".Trim()
    # 🪤 Graph lags behind ARM: a principal minted seconds ago is often not yet resolvable, and the
    # lookup returns EMPTY rather than erroring -- which would silently produce an empty SID and a
    # contained user that can never authenticate. Wait for it instead of accepting the blank.
    $newAppId = ''
    if ($newPid) {
        for ($i = 0; $i -lt 12 -and -not $newAppId; $i++) {
            $newAppId = "$((Get-PimGraphServicePrincipal -Id $newPid -Select 'appId' -ErrorAsNull).appId)".Trim()
            if (-not $newAppId) { Start-Sleep -Seconds 5 }
        }
    }
    $identNow += @{ name=$b.name; principalId=$newPid; appId=$newAppId }
    Say ("  {0,-16} {1}" -f $b.name, $(if ($newPid -and $newPid -ne $b.principalId) { "principal CHANGED $($b.principalId) -> $newPid" }
                                        elseif ($newPid) { 'principal unchanged' } else { 'NO system-assigned identity' })) `
        $(if ($newPid -and $newPid -ne $b.principalId) { 'Yellow' } elseif ($newPid) { 'Green' } else { 'Red' })
}

$plan = Get-PimIdentityRepairPlan -Before $script:IdentBefore -Now $identNow -SqlUsers $script:SqlUsersBefore
foreach ($p in @($plan.problems)) { Bad $p }
if ($script:fail) { throw 'could not resolve the new identities -- stopping before anything is exposed.' }
Say ("  plan: {0} role assignment(s), {1} SQL user(s) to remap, {2} unchanged" -f `
        @($plan.roleGrants).Count, @($plan.sqlRemaps).Count, @($plan.unchanged).Count) 'Green'

# ---- (a) Azure role assignments ----------------------------------------------------------------
# The old principal's assignments died with it. Re-create each recorded (role, scope) pair against
# the new principal, and treat "already exists" as success -- a re-run must be a no-op.
Step '6c-a. role assignments'
$raDone = 0
foreach ($g in @($plan.roleGrants)) {
    $ra = $null; $out = ''
    try { $ra = New-PimArmRoleAssignment -Scope "$($g.scope)" -PrincipalId $g.principalId -PrincipalType ServicePrincipal -Role "$($g.role)" -SubscriptionId $SubscriptionId }
    catch { $out = "$($_.Exception.Message)" }
    if ($ra -and $ra.PSObject.Properties['existed']) { $raDone++; Say "    = $($g.role) already present" 'DarkGray' }
    elseif (-not $out)                                { $raDone++; Say "    + $($g.role) on $($g.scope)" 'Green' }
    else { Bad "could not grant '$($g.role)' on '$($g.scope)' to $($g.name): $out" }
}
Say ("  {0} of {1} assignment(s) in place" -f $raDone, @($plan.roleGrants).Count) 'Green'

# ---- (b) SQL contained users --------------------------------------------------------------------
# A user's SID cannot be altered in place, so this is drop + create, with the recorded role
# memberships re-applied. Nothing but principals is touched: no table, no row, no schema.
Step '6c-b. SQL contained users'
if (-not @($plan.sqlRemaps).Count) { Say '  no contained user needs remapping' 'DarkGray' }
else {
    $conn = $null
    try { $conn = Get-SqlConn } catch { Bad "could not connect to SQL for the repair: $($_.Exception.Message)" }
    if (-not $conn) {
        Bad ("$(@($plan.sqlRemaps).Count) SQL user(s) need remapping but NO usable SQL credential was given. " +
             "The Manager will crash-loop on: Login failed for user '<token-identified principal>'. " +
             "Re-run with -SqlServer/-SqlAdminClientId/-SqlAdminClientSecret, or remap by hand.")
    } else {
        try {
            foreach ($r in @($plan.sqlRemaps)) {
                $safe = $r.name -replace ']',']]'
                $lit  = $r.name -replace "'","''"
                # A user that owns a schema cannot be dropped. Move ownership to dbo first --
                # otherwise the DROP fails and the repair stops half-done.
                SqlExec $conn @"
DECLARE @s sysname;
DECLARE c CURSOR FOR SELECT s.name FROM sys.schemas s JOIN sys.database_principals p ON p.principal_id=s.principal_id WHERE p.name=N'$lit';
OPEN c; FETCH NEXT FROM c INTO @s;
WHILE @@FETCH_STATUS=0 BEGIN EXEC('ALTER AUTHORIZATION ON SCHEMA::['+@s+'] TO dbo'); FETCH NEXT FROM c INTO @s; END
CLOSE c; DEALLOCATE c;
"@
                SqlExec $conn "DROP USER [$safe];"
                SqlExec $conn "CREATE USER [$safe] WITH SID = $($r.newSid), TYPE = E;"
                foreach ($role in @($r.roles)) { SqlExec $conn "ALTER ROLE [$($role -replace ']',']]')] ADD MEMBER [$safe];" }
                Say "    $($r.name): $($r.oldSid) -> $($r.newSid) (roles: $(@($r.roles) -join ', '))" 'Green'
            }
            # VERIFY, never assume. Read every remapped user back, SID and role memberships both --
            # a user that authenticates and can read nothing is harder to spot than one that cannot
            # log in at all.
            foreach ($r in @($plan.sqlRemaps)) {
                $lit = $r.name -replace "'","''"
                $got = @(SqlRows $conn @"
SELECT CONVERT(varchar(100),p.sid,1) AS sid,
       ISNULL(STUFF((SELECT ',' + ro.name FROM sys.database_role_members m
              JOIN sys.database_principals ro ON ro.principal_id = m.role_principal_id
              WHERE m.member_principal_id = p.principal_id ORDER BY ro.name FOR XML PATH('')),1,1,''),'') AS roles
FROM sys.database_principals p WHERE p.name = N'$lit'
"@)
                if (-not $got.Count) { Bad "SQL user '$($r.name)' is GONE after the repair"; continue }
                if ("$($got[0].sid)" -ine $r.newSid) { Bad "SQL user '$($r.name)' has sid $($got[0].sid), expected $($r.newSid)"; continue }
                $wantRoles = (@($r.roles) | Sort-Object) -join ','
                $gotRoles  = (@("$($got[0].roles)".Split(',') | Where-Object { "$_".Trim() }) | Sort-Object) -join ','
                if ($wantRoles -ne $gotRoles) { Bad "SQL user '$($r.name)' roles are '$gotRoles', expected '$wantRoles'"; continue }
                Say "    verified $($r.name) -> $($r.newSid) [$gotRoles]" 'Green'
            }
        } finally { $conn.Close() }
    }
}
if ($script:fail) { throw "identity repair did not complete ($script:fail problem(s)) -- NOT exposing this environment." }
Say 'identity-keyed state repaired and verified' 'Green'
}

# =================================================================================================
# 7. PROVE THE RESTORE IS FAITHFUL. "Recreated" is a claim; a diff is evidence.
# =================================================================================================
# =================================================================================================
# 6d. §92 NET-1 -- the GRAPH app roles of the NEW identities. 6c repairs SQL users and Azure role
#     assignments; the tick's Engine roles and the Manager's read-only roles are Graph app-role
#     assignments on the OLD principals and vanished with them. Without this the engine runs and is
#     refused by Graph on every call.
# =================================================================================================
if ("$HostingAccessTenantId".Trim() -and "$SqlServer".Trim()) {
    Step '6d. re-grant the Graph app roles + tick-start rights of the NEW identities (Initialize-PimHostingAccess)'
    $hostAccess = Join-Path $here 'Initialize-PimHostingAccess.ps1'
    $ha = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; SqlServerFqdn = $(if ($SqlServer -match '\.') { $SqlServer } else { "$SqlServer.database.windows.net" }); SqlDatabase = $SqlDatabase; TenantId = $HostingAccessTenantId }
    if ("$HostingAccessClientId".Trim()) { $ha['ClientId'] = $HostingAccessClientId }
    if ("$HostingAccessCertThumbprint".Trim()) { $ha['CertThumbprint'] = $HostingAccessCertThumbprint }
    & $hostAccess @ha
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { Bad "Initialize-PimHostingAccess failed (exit $LASTEXITCODE) -- the new identities may lack their Graph roles; re-run it before relying on the engine." }
} else {
    Step '6d. Graph app roles of the NEW identities -- NOT re-granted here'
    Warn ("re-run: tools\setup\Initialize-PimHostingAccess.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup " +
          "-SqlServerFqdn <server>.database.windows.net -TenantId <tenant> -ClientId <cert SPN> -CertThumbprint <thumb>")
}

Step '7. verify the restore against the capture'
$now = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
function Cmp($what, $a, $b) {
    if ("$a" -eq "$b") { Say "  same: $what" } else { Bad "DIFFERS: $what  was='$a' now='$b'" }
}
Cmp 'image'        $appCap.properties.template.containers[0].image $now.properties.template.containers[0].image
Cmp 'cpu'          $appCap.properties.template.containers[0].resources.cpu $now.properties.template.containers[0].resources.cpu
Cmp 'memory'       $appCap.properties.template.containers[0].resources.memory $now.properties.template.containers[0].resources.memory
Cmp 'minReplicas'  $appCap.properties.template.scale.minReplicas $now.properties.template.scale.minReplicas
Cmp 'maxReplicas'  $appCap.properties.template.scale.maxReplicas $now.properties.template.scale.maxReplicas
Cmp 'targetPort'   $appCap.properties.configuration.ingress.targetPort $now.properties.configuration.ingress.targetPort
Cmp 'env var count' @($appCap.properties.template.containers[0].env).Count @($now.properties.template.containers[0].env).Count
Cmp 'secret count'  @($appCap.properties.configuration.secrets).Count @($now.properties.configuration.secrets).Count
Cmp 'registry'      $appCap.properties.configuration.registries[0].server $now.properties.configuration.registries[0].server
Cmp 'identity type' $appCap.identity.type $now.identity.type
# Every environment variable, by name AND value -- an env var that quietly went missing is the
# failure this whole restore path could produce and still look healthy.
$wasEnv = @{}; foreach ($e in @($appCap.properties.template.containers[0].env)) { $wasEnv[$e.name] = "$($e.value)$($e.secretRef)" }
$nowEnv = @{}; foreach ($e in @($now.properties.template.containers[0].env))    { $nowEnv[$e.name] = "$($e.value)$($e.secretRef)" }
foreach ($k in $wasEnv.Keys) {
    if (-not $nowEnv.ContainsKey($k)) { Bad "env var MISSING after restore: $k" }
    elseif ($wasEnv[$k] -ne $nowEnv[$k]) { Bad "env var CHANGED after restore: $k" }
}
if ($script:fail) { throw "the restore does not match the capture ($script:fail difference(s)) -- NOT exposing this app." }
Say 'restore matches the capture' 'Green'

# =================================================================================================
# 7b. CUSTOM DOMAIN -- bound BEFORE Easy Auth, so auth is configured against the FINAL name.
# =================================================================================================
$publicHost = $null
if ("$CustomDomain".Trim()) {
    Step "7b. bind the custom domain '$CustomDomain'"
    # 🪤 READ THE VERIFICATION ID FROM THE APP THAT EXISTS NOW, never from the capture. It is a
    # per-app value, and this app was just recreated -- a stale id makes the TXT record fail
    # validation with a message about DNS, sending you to debug the zone instead of the value.
    $appNow = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
    $vid = "$($appNow.properties.customDomainVerificationId)"
    $acaFqdn = "$($appNow.properties.configuration.ingress.fqdn)"
    $sub1 = ("$CustomDomain".Split('.')[0])
    Write-Host ''
    Write-Host '  CREATE THESE TWO DNS RECORDS (only you can do this):' -ForegroundColor Yellow
    Write-Host ("    CNAME  {0,-34} ->  {1}" -f $CustomDomain, $acaFqdn) -ForegroundColor White
    Write-Host ("    TXT    {0,-34} ->  {1}" -f "asuid.$sub1", $vid) -ForegroundColor White
    Write-Host '  The TXT proves you own the domain; the CNAME points it at this app.' -ForegroundColor DarkGray
    Write-Host ''
    if (-not $CustomDomainDnsReady) {
        Write-Host '  Waiting for those records. Press Enter once they are live (Ctrl+C to stop here' -ForegroundColor Yellow
        Write-Host '  -- the Manager stays INTERNAL and nothing is exposed).' -ForegroundColor Yellow
        [void](Read-Host '  press Enter when DNS is ready')
    }
    Invoke-Checked "add hostname '$CustomDomain'" {
        Set-PimArmAcaAppCustomDomain -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -HostName $CustomDomain
    }
    # A free MANAGED certificate. CNAME validation matches the record we just asked for, so there
    # is nothing extra to publish.
    $certName = ($CustomDomain -replace '[^A-Za-z0-9-]', '-')
    $script:mcert = $null
    Invoke-Checked "managed certificate for '$CustomDomain'" {
        $script:mcert = New-PimArmAcaManagedCertificate -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -EnvironmentName $EnvName -Name $certName -HostName $CustomDomain -Location $location
    }
    Invoke-Checked "bind '$CustomDomain'" {
        Set-PimArmAcaAppCustomDomain -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -HostName $CustomDomain -CertificateId "$($script:mcert.id)"
    }
    $publicHost = $CustomDomain
    Say "bound. the stable address is https://$CustomDomain" 'Green'
}

# =================================================================================================
# 8. EASY AUTH -- before the app is reachable, never after.
# =================================================================================================
if ($SkipEasyAuth) {
    Step '8. Easy Auth SKIPPED by request -- the Manager stays on INTERNAL ingress'
    Warn "attach auth, then expose '$ManagerApp' (ingress external) -- e.g. re-run this script without -SkipEasyAuth, or Set-PimManagerEasyAuth.ps1."
} else {
    Step '8. attach Easy Auth to the NEW FQDN'
    $easyAuth = Join-Path $here 'Set-PimManagerEasyAuth.ps1'
    if (-not (Test-Path -LiteralPath $easyAuth)) { throw "Set-PimManagerEasyAuth.ps1 not found beside this script." }
    $tid = $(if ("$EasyAuthTenantId".Trim()) { $EasyAuthTenantId } else { $authCap.identityProviders.azureActiveDirectory.registration.openIdIssuer -replace '^https://login\.microsoftonline\.com/','' -replace '/v2\.0$','' })
    # 🪤 The parameter is -App, NOT -AppName. Calling it wrong fails HERE -- after the environment
    # has been deleted and recreated -- which is the worst possible place to discover a typo.
    # SEC-44: who may sign in is an explicit choice there too -- forwarded, never defaulted here. An
    # app that is already assignment-required keeps its assignments without either.
    $eaChoice = @{}
    if (@($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count) { $eaChoice['AllowedPrincipals'] = @($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }) }
    if ($EasyAuthAllowAllTenantUsers) { $eaChoice['AllowAllTenantUsers'] = $true }
    & $easyAuth -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -App $ManagerApp -TenantId $tid @eaChoice
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Set-PimManagerEasyAuth failed (exit $LASTEXITCODE) -- NOT exposing this app." }

    # 🔒 PROVE IT before exposing. A failed auth attach that returns 0 would otherwise publish the
    # Manager wide open, which is the exact outcome this script exists to prevent.
    $authNow = (Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull).properties
    $boundId = $authNow.identityProviders.azureActiveDirectory.registration.clientId
    if (-not $boundId) { throw "Easy Auth is still not configured on '$ManagerApp' -- REFUSING to expose it." }
    if ("$($authNow.globalValidation.unauthenticatedClientAction)" -notmatch 'RedirectToLoginPage|Return401|Return403') {
        throw "Easy Auth is configured but unauthenticated callers are not challenged -- REFUSING to expose."
    }
    Say "Easy Auth bound to $boundId (unauth -> $($authNow.globalValidation.unauthenticatedClientAction))" 'Green'

    Step '9. expose the Manager (ingress -> external)'
    # SEC-35: checked AND read back. This flip used to be a bare call whose failure nobody saw, so the
    # run printed a "public FQDN" for an app that was still internal -- or, worse, never noticed which.
    Invoke-Checked "switch '$ManagerApp' to external ingress" {
        Set-PimArmAcaAppConfiguration -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate { param($cfg) $cfg.ingress.external = $true }
    }
    $appExt = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
    $extNow = "$($appExt.properties.configuration.ingress.external)".Trim()
    $fq = "$($appExt.properties.configuration.ingress.fqdn)".Trim()
    if ($extNow -notmatch '(?i)^true$' -or -not $fq) { throw "read-back: '$ManagerApp' ingress.external='$extNow' fqdn='$fq' after the switch -- the Manager is NOT exposed as intended." }
    Say "public FQDN  : https://$fq (ingress external, read back)" 'Green'
}

# =================================================================================================
# 10. the private DNS zone for the OLD domain -- it shadows the new public name inside the VNet.
# =================================================================================================
if ($wantInternal) {
    # §92 NET-2: an internal-only environment publishes its apps at ONE private static IP that nothing off the
    # subnet resolves -- the zone is what makes the Manager reachable at all from the VNet and its peers.
    Step "10. private DNS zone for the NEW domain '$newDomain' -> $($newEnv.properties.staticIp)"
    $reach = Join-Path $sol 'engine\_shared\PIM-Reachability.ps1'
    if (-not (Get-Command Get-PimPrivateDnsPlan -ErrorAction SilentlyContinue)) { . $reach }
    if (-not (Get-Command Set-PimPrivateDnsZone -ErrorAction SilentlyContinue)) {
        # ONLY this function from the setup library -- dot-sourcing the whole file would also install its guarded az wrapper
        $tk = $null; $pe = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $here '_PimSetupShared.ps1'), [ref]$tk, [ref]$pe)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Set-PimPrivateDnsZone' }, $true)
        if (-not $fn) { throw 'Set-PimPrivateDnsZone not found in _PimSetupShared.ps1' }
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    $vnetOfSubnet = ($subnetId -replace '/subnets/[^/]+$', '')
    $links = @(@($vnetOfSubnet) + @($HubVnetId | Where-Object { "$_".Trim() }) | Select-Object -Unique)
    $dnsRg = $(if ("$PrivateDnsResourceGroup".Trim()) { $PrivateDnsResourceGroup } else { $ResourceGroup })
    Set-PimPrivateDnsZone -EnvDomain $newDomain -StaticIp "$($newEnv.properties.staticIp)" -ResourceGroup $dnsRg -SubscriptionId $SubscriptionId -LinkVnetIds $links
    if (-not @($HubVnetId).Count) { Warn 'no -HubVnetId: only the spoke VNet resolves the Manager. Link the hub (or add the record to your AD DNS) for clients outside it.' }
    # §92 NET-3: the registry (only on request, only when safe) and what the store still needs
    foreach ($r in @(RgList 'Microsoft.ContainerRegistry/registries' acr)) {
        $d = Get-PimRegistryLockDecision -Sku "$($r.sku.name)" -PublicNetworkAccess "$($r.properties.publicNetworkAccess)" -PrivateEndpointCount @($r.properties.privateEndpointConnections | Where-Object { $_ }).Count -Requested:$LockRegistry
        if ($d.lock) {
            Invoke-Checked "turn public network access OFF on registry '$($r.name)'" { Update-PimArmAcr -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $r.name -Properties @{ publicNetworkAccess = 'Disabled' } }
            $pna = "$((Get-PimArmAcr -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $r.name -ErrorAsNull).properties.publicNetworkAccess)".Trim()
            if ($pna -ne 'Disabled') { Bad "registry '$($r.name)' still reports publicNetworkAccess=$pna after the switch" } else { Say "registry $($r.name): public network access OFF (read back)" 'Green' }
        } else { Say "registry $($r.name): $($d.reason)" 'Yellow' }
    }
    foreach ($n in @(Get-PimInternalSwitchNotes | Where-Object { $_ -like 'sql *' })) { Warn $n }
} elseif ($staleZone -and -not $KeepOldPrivateDnsZone) {
    Step "10. remove the stale private DNS zone '$oldDomain'"
    # Links must go first; a zone with virtual-network links refuses to delete. A refused delete is reported, not fatal.
    foreach ($lnk in @(Get-PimArmPrivateDnsLinks -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ZoneName $oldDomain -ErrorAsNull)) {
        Say "unlinking $($lnk.name)"
        try { Remove-PimArmResource -ResourceId "$($lnk.id)" -Kind privateDns -Wait -TimeoutSeconds 600 } catch { Warn "unlink $($lnk.name): $($_.Exception.Message)" }
    }
    try { Remove-PimArmResource -ResourceId (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/privateDnsZones' $oldDomain) -Kind privateDns -Wait -TimeoutSeconds 600 } catch { Warn "zone delete: $($_.Exception.Message)" }
    Say 'removed.' 'Green'
} elseif ($staleZone) {
    Warn "private DNS zone '$oldDomain' KEPT by request -- it will shadow the new public name for VNet clients."
}

# =================================================================================================
# 11. RE-VERIFY THE KEEP-LIST. The whole point of a rebuild on a sensitive environment is that the
#     DATA survives it. Prove that, do not assert it.
# =================================================================================================
Step '11. re-verify everything that holds data is still there'
$keepAfter = Get-PimKeepList
$lost = 0
foreach ($k in $script:KeepBefore.Keys) {
    $missing = @(@($script:KeepBefore[$k]) | Where-Object { $_ -and ($keepAfter[$k] -notcontains $_) })
    if ($missing.Count) { Bad ("$k MISSING after the rebuild: " + ($missing -join ', ')); $lost += $missing.Count }
    else { Say ("  {0,-14} intact ({1})" -f $k, @($script:KeepBefore[$k]).Count) 'Green' }
}
if ($lost) {
    throw ("$lost item(s) that hold DATA are missing after this rebuild. Nothing in this script deletes " +
           "them, so this is not an expected outcome -- investigate before touching anything else.")
}
Say 'every data-bearing resource that existed before this rebuild still exists.' 'Green'

# SEC-35: the rebuild is complete, so nothing is left to resume -- the secret captures go too.
foreach ($sf in @($script:SecretFilesToShred | Select-Object -Unique)) { Remove-PimSecretFile $sf }
foreach ($sf in @(Get-ChildItem -LiteralPath $CaptureDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Tag-restore-*" -or $_.Name -like "$Tag-*-secrets*.json" })) { Remove-PimSecretFile $sf.FullName }

Step 'REBUILD COMPLETE'
Say "old domain : $oldDomain"
Say "new domain : $newDomain" 'Green'
Say "capture    : $CaptureDir (configuration only -- every file that held a secret value was shredded)"
if (-not $SkipEasyAuth) { Say $(if ($wantInternal) { 'verify FROM A VNET / HUB CLIENT: the FQDN should answer 302 to Entra, never 200 (from the internet it must not resolve or answer).' } else { 'verify: the public FQDN should answer 302 to Entra, never 200.' }) 'Yellow' }
# §92 NET-4: what the rebuild cannot see and does not remove
Warn "leftovers to remove by hand: reply URLs for *.$oldDomain on the Manager's Entra app registration; any AD / public DNS record for $oldDomain or a custom domain pointing at it."

