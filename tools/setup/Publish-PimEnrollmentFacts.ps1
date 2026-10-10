#Requires -Version 5.1
<#
.SYNOPSIS
    UPLINK-ENROL (PIM 99) -- record and REPORT what self-service managed tenants need, for one environment:
      -Role Master  the managing tenant's bundle facts (store, container, the signing key ids its Manager pins), and the
                    tick's right to manage the network rules of that ONE storage account (the enrolled-tenants job)
      -Role Slave   the managed tenant's pull subnet id (printed by its pullnetwork step)

.DESCRIPTION
    Run by the one-shot MSP build (Invoke-PimMspBuild.ps1): step 'enrollment' on the managing tenant, step 'enrollreport' on a
    managed tenant built with an enrollment key. Safe to run again by hand (every part converges).

      1. (Master, public-but-signed store) a custom role 'PIM Manager bundle store network rules - <account>' with ONLY
         Microsoft.Storage/storageAccounts/read + /write, assignable to that one account, assigned to the tick's managed
         identity. Network rules are a property of the storage account, so /write is the narrowest action Azure offers;
         the role grants no data access, no keys (listKeys is a separate action) and nothing outside that account.
      2. pim.Settings 'MspBundleFacts' (Master) or 'MspPullSubnetId' (Slave), read back, audited (msp.enrollment.facts).
      3. PUT {Invardia}/api/enrollments/facts with this environment's OWN install key (header X-Invardia-Install-Key);
         facts always writes the caller's own environment. Master: { product, bundleStorage, container, signingKeyIds } --
         no key yet or a report that does not land is a warning (the daily enrolled-tenants job repeats it). Slave:
         { product, pullSubnetIds } -- a missing key or a refusal FAILS the step: nobody else gives the managing tenant
         this subnet.

    No secret is read from or written to the config; the install key is read from the store and only sent as the header.

.PARAMETER TickPrincipalId
    The object id of the tick's system-assigned managed identity (the build resolves {{mi-job:ca-pim-tick}}).
.PARAMETER Access
    publicSigned (default) or privateEndpoint -- over a private endpoint there are no network rules to manage, so no role.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Master', 'Slave')][string]$Role,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$TickPrincipalId,
    [ValidateSet('publicSigned', 'privateEndpoint')][string]$Access = 'publicSigned',
    # Master: the signing key id(s) (43-char RFC 7638 thumbprints; identifiers, not secrets). The managing tenant's Manager
    # pins NO key (only managed tenants pin the master's key), so the pin cannot be the source there: the build passes the
    # id its signingkey step printed (master config `signingKeyIds`). The Manager's pin stays the fallback (live 2026-10-08).
    [string[]]$SigningKeyIds = @(),
    [string]$PullSubnetId,
    [string]$InvardiaBaseUrl = ''
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$__enrollLib = Join-Path $solRoot 'engine\msp\PIM-InvardiaEnrollment.ps1'
if (-not (Test-Path -LiteralPath $__enrollLib)) { throw 'Self-service managed tenants (enrollment) are part of PIM Manager Pro (MSP) -- this edition does not include them.' }
. $__enrollLib
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m, $c = 'DarkGray') { Write-Host "    $m" -ForegroundColor $c }

$keyIds = @()
if ($Role -eq 'Master') {
    foreach ($p in @(@{ n = 'SubscriptionId'; v = $SubscriptionId }, @{ n = 'ResourceGroup'; v = $ResourceGroup }, @{ n = 'StorageAccount'; v = $StorageAccount })) {
        if (-not "$($p.v)".Trim()) { throw "-$($p.n) is required for -Role Master" }
    }
    # 100.41 (NO-AZ): ARM REST (engine/_shared/PIM-ArmSetup.ps1) over PIM-Rest's ONE token client -- the certificate
    # identity, or the signed-in one (the Invardia Support app's REST session / the browser). No az CLI.
    if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
    if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
    $subId = "$SubscriptionId".Trim()
    if (-not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) {
        if ("$ClientId".Trim() -and "$CertThumbprint".Trim() -and -not $UseSignedInAccount) { [void](Connect-PimSetupRest -SubscriptionId $subId -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint) }
        else { [void](Connect-PimSetupRest -SubscriptionId $subId -TenantId $TenantId) }
    }
    $acctObj = Get-PimArmStorageAccount -SubscriptionId $subId -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull
    $acctId = if ($acctObj) { "$($acctObj.id)".Trim() } else { '' }
    if (-not $acctId) { throw "storage account '$StorageAccount' not found in $ResourceGroup -- run the build's storage step first" }

    if ($Access -eq 'publicSigned') {
        Step "the tick may manage the network rules of $StorageAccount (and nothing else)"
        if ("$TickPrincipalId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { throw '-TickPrincipalId must be the object id of the tick''s managed identity' }
        $roleName = "PIM Manager bundle store network rules - $StorageAccount"
        $authApi = Get-PimSetupApiVersion authorization
        # az role definition list --name N --scope S --custom-role-only true
        $findRole = {
            $f = [uri]::EscapeDataString("roleName eq '$($roleName.Replace("'", "''"))'")
            $d = @(Invoke-PimSetupArm -Path "$acctId/providers/Microsoft.Authorization/roleDefinitions?`$filter=$f" -ApiVersion $authApi -All -ErrorAsNull)
            @($d | Where-Object { $_ -and "$($_.properties.type)" -eq 'CustomRole' -and "$($_.properties.roleName)" -eq $roleName }) | Select-Object -First 1
        }
        $haveRole = & $findRole
        if (-not $haveRole) {
            $def = [ordered]@{ Name = $roleName; IsCustom = $true
                               Description = 'PIM Manager enrolled-tenants job: read the bundle store and set its network rules. No data access, no keys, this storage account only.'
                               Actions = @('Microsoft.Storage/storageAccounts/read', 'Microsoft.Storage/storageAccounts/write'); NotActions = @(); DataActions = @(); NotDataActions = @()
                               AssignableScopes = @($acctId) }
            # az role definition create = PUT roleDefinitions/<new guid> at the account scope, the same definition in ARM's shape.
            $roleGuid = [guid]::NewGuid().ToString()
            $body = @{ properties = @{ roleName = $def.Name; description = $def.Description; type = 'CustomRole'; assignableScopes = @($def.AssignableScopes)
                                       permissions = @(@{ actions = @($def.Actions); notActions = @(); dataActions = @(); notDataActions = @() }) } }
            try { [void](Invoke-PimSetupArm -Method PUT -Path "$acctId/providers/Microsoft.Authorization/roleDefinitions/$roleGuid" -Body $body -ApiVersion $authApi) }
            catch { throw "could not create the custom role '$roleName' ($($_.Exception.Message)) -- the build identity needs Owner or User Access Administrator on the subscription" }
            Note "custom role created: $roleName"
            $haveRole = [pscustomobject]@{ name = $roleGuid; id = "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions/$roleGuid" }
        } else { Note "custom role present: $roleName" }
        $roleDefGuid = "$($haveRole.name)".Trim().ToLowerInvariant()
        $haveAsg = @()
        try { $haveAsg = @(Get-PimArmRoleAssignments -SubscriptionId $subId -PrincipalId $TickPrincipalId -Scope $acctId | Where-Object { (("$($_.roleDefinitionId)" -split '/')[-1]).ToLowerInvariant() -eq $roleDefGuid }) } catch { $haveAsg = @() }
        if ($haveAsg.Count) { Note 'the tick already holds it' }
        else {
            # A new custom role takes a moment to replicate; the assignment is retried on that one error only.
            $ok = $false
            for ($try = 1; $try -le 12 -and -not $ok; $try++) {
                $out = ''
                try { [void](New-PimArmRoleAssignment -SubscriptionId $subId -PrincipalId $TickPrincipalId -PrincipalType ServicePrincipal -Role "/subscriptions/$subId/providers/Microsoft.Authorization/roleDefinitions/$roleDefGuid" -Scope $acctId); $ok = $true; break }
                catch { $out = "$($_.Exception.Message)" }
                if ("$out" -notmatch '(?i)does not exist|RoleDefinitionDoesNotExist|not found') { throw "could not assign '$roleName' to the tick: $out" }
                Note "the new role has not replicated yet -- retry $try/12 in 15s"
                Start-Sleep -Seconds 15
            }
            if (-not $ok) { throw "the role '$roleName' could not be assigned within 3 minutes -- re-run this step (idempotent)" }
            Note 'assigned to the tick''s managed identity'
        }
    } else { Note 'private-endpoint store: no network rules to manage (managed tenants reach it over VNet peering) -- no role granted' }

    Step "the signing key ids $ManagerApp pins (the signingkey step pinned them)"
    $mgrObj = Get-PimArmAcaApp -SubscriptionId $subId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
    $envList = @(); try { $envList = @(@($mgrObj.properties.template.containers)[0].env | Where-Object { $_ }) } catch { $envList = @() }
    $pinVal = "$(@($envList | Where-Object { "$($_.name)" -eq 'PIM_BaselineTrustedKeys' }) | Select-Object -First 1 | ForEach-Object { $_.value })"
    $keyIds = @("$pinVal" -split '[,;\s]+' | Where-Object { $_ -cmatch '^[A-Za-z0-9_-]{43}$' })
    $given = @(@($SigningKeyIds) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $badGiven = @($given | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_-]{43}$' })
    if ($badGiven.Count) { throw "-SigningKeyIds: not a signing key id (43 characters, base64url): $($badGiven -join ', ')" }
    if ($given.Count) { $keyIds = @($given + $keyIds | Select-Object -Unique) }
    if (-not $keyIds.Count) { throw "no signing key id: pass -SigningKeyIds (the id the build's signingkey step printed, master config signingKeyIds) -- the managing tenant's Manager pins none" }
    Note "pinned: $($keyIds -join ', ')"
}

Step "record$(if ($Role -eq 'Master') { ' the bundle facts' } else { ' the pull subnet id' }) in the store and report to Invardia"
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
$cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
$get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
$set = { param($n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v }
$http = { param($m, $u, $b, $h) Invoke-PimEnrollmentHttp -Method $m -Url $u -Body $b -Headers $h }
$r = Invoke-PimEnrollmentFactsPublish -Role $Role -GetSetting $get -SetSetting $set -Http $http -BaseUrl $InvardiaBaseUrl `
        -StorageAccount $StorageAccount -Container $Container -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Access $Access `
        -SigningKeyIds $keyIds -PullSubnetId $PullSubnetId
if (-not $r.ok) {
    Write-Host "RESULT: FAILED -- $($r.reason)" -ForegroundColor Red
    if ($Role -eq 'Slave' -and $r.stored) {
        Write-Host '  Meanwhile the managing company can allow this subnet by hand (an address, not a credential):' -ForegroundColor Yellow
        Write-Host "    managed tenants[<n>].subnetResourceId = $PullSubnetId" -ForegroundColor Yellow
    }
    exit 1
}
$after = if ($Role -eq 'Master') { @{ storageAccount = $StorageAccount; container = $Container; signingKeyIds = @($keyIds); access = $Access; reported = $r.reported } } else { @{ pullSubnetId = $PullSubnetId; reported = $r.reported } }
Write-PimSetupAudit -ConnectionString $cs -Action 'msp.enrollment.facts' -Target $(if ($Role -eq 'Master') { "$StorageAccount/$Container" } else { "$PullSubnetId" }) -After $after
Note $r.reason $(if ($r.reported) { 'Gray' } else { 'Yellow' })
Write-Host "RESULT: OK -- $($r.reason)" -ForegroundColor Green
exit 0
