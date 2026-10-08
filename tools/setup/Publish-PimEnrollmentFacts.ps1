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
    [string]$PullSubnetId,
    [string]$InvardiaBaseUrl = ''
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\msp\PIM-InvardiaEnrollment.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m, $c = 'DarkGray') { Write-Host "    $m" -ForegroundColor $c }

$keyIds = @()
if ($Role -eq 'Master') {
    foreach ($p in @(@{ n = 'SubscriptionId'; v = $SubscriptionId }, @{ n = 'ResourceGroup'; v = $ResourceGroup }, @{ n = 'StorageAccount'; v = $StorageAccount })) {
        if (-not "$($p.v)".Trim()) { throw "-$($p.n) is required for -Role Master" }
    }
    $sub = @('--subscription', "$SubscriptionId".Trim())
    $ErrorActionPreference = 'Continue'
    $acctId = "$(az storage account show @sub -g $ResourceGroup -n $StorageAccount --query id -o tsv --only-show-errors 2>$null)".Trim()
    $ErrorActionPreference = 'Stop'
    if (-not $acctId) { throw "storage account '$StorageAccount' not found in $ResourceGroup -- run the build's storage step first" }

    if ($Access -eq 'publicSigned') {
        Step "the tick may manage the network rules of $StorageAccount (and nothing else)"
        if ("$TickPrincipalId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { throw '-TickPrincipalId must be the object id of the tick''s managed identity' }
        $roleName = "PIM Manager bundle store network rules - $StorageAccount"
        $ErrorActionPreference = 'Continue'
        $haveRole = "$(az role definition list @sub --name $roleName --scope $acctId --custom-role-only true --query '[0].name' -o tsv --only-show-errors 2>$null)".Trim()
        $ErrorActionPreference = 'Stop'
        if (-not $haveRole) {
            $def = [ordered]@{ Name = $roleName; IsCustom = $true
                               Description = 'PIM Manager enrolled-tenants job: read the bundle store and set its network rules. No data access, no keys, this storage account only.'
                               Actions = @('Microsoft.Storage/storageAccounts/read', 'Microsoft.Storage/storageAccounts/write'); NotActions = @(); DataActions = @(); NotDataActions = @()
                               AssignableScopes = @($acctId) }
            # A FILE, not an inline argument: az is az.cmd on Windows and drops everything after the first line of an argument.
            $defFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-role-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
            try {
                ConvertTo-Json -InputObject $def -Depth 5 | Set-Content -LiteralPath $defFile -Encoding ASCII
                $ErrorActionPreference = 'Continue'
                az role definition create @sub --role-definition "@$defFile" -o none --only-show-errors
                $code = $LASTEXITCODE
                $ErrorActionPreference = 'Stop'
                if ($code -ne 0) { throw "could not create the custom role '$roleName' (az exit $code) -- the build identity needs Owner or User Access Administrator on the subscription" }
            } finally { Remove-Item -LiteralPath $defFile -Force -ErrorAction SilentlyContinue }
            Note "custom role created: $roleName"
        } else { Note "custom role present: $roleName" }
        $ErrorActionPreference = 'Continue'
        $haveAsg = @(az role assignment list @sub --assignee $TickPrincipalId --scope $acctId --query '[].roleDefinitionName' -o tsv --only-show-errors 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ -eq $roleName })
        $ErrorActionPreference = 'Stop'
        if ($haveAsg.Count) { Note 'the tick already holds it' }
        else {
            # A new custom role takes a moment to replicate; the assignment is retried on that one error only.
            $ok = $false
            for ($try = 1; $try -le 12 -and -not $ok; $try++) {
                $ErrorActionPreference = 'Continue'
                $out = az role assignment create @sub --assignee-object-id $TickPrincipalId --assignee-principal-type ServicePrincipal --role $roleName --scope $acctId -o none --only-show-errors 2>&1
                $code = $LASTEXITCODE
                $ErrorActionPreference = 'Stop'
                if ($code -eq 0) { $ok = $true; break }
                if ("$out" -notmatch '(?i)does not exist|RoleDefinitionDoesNotExist|not found') { throw "could not assign '$roleName' to the tick (az exit $code): $out" }
                Note "the new role has not replicated yet -- retry $try/12 in 15s"
                Start-Sleep -Seconds 15
            }
            if (-not $ok) { throw "the role '$roleName' could not be assigned within 3 minutes -- re-run this step (idempotent)" }
            Note 'assigned to the tick''s managed identity'
        }
    } else { Note 'private-endpoint store: no network rules to manage (managed tenants reach it over VNet peering) -- no role granted' }

    Step "the signing key ids $ManagerApp pins (the signingkey step pinned them)"
    $ErrorActionPreference = 'Continue'
    $envJson = az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].env' -o json --only-show-errors 2>$null | Out-String
    $ErrorActionPreference = 'Stop'
    $envList = @(); try { $envList = @("$envJson" | ConvertFrom-Json) } catch { $envList = @() }
    $pinVal = "$(@($envList | Where-Object { "$($_.name)" -eq 'PIM_BaselineTrustedKeys' }) | Select-Object -First 1 | ForEach-Object { $_.value })"
    $keyIds = @("$pinVal" -split '[,;\s]+' | Where-Object { $_ -cmatch '^[A-Za-z0-9_-]{43}$' })
    if (-not $keyIds.Count) { throw "$ManagerApp pins no signing key id (PIM_BaselineTrustedKeys) -- run the build's signingkey step first" }
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
