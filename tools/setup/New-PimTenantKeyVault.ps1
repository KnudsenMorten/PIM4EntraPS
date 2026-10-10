#Requires -Version 5.1
<#
.SYNOPSIS
    The tenant Key Vault of a one-shot MSP build (RBAC mode + soft-delete + purge protection), and the bootstrap
    identity's READ grant on it ('Key Vault Secrets User') -- over ARM + Graph REST, no PowerShell modules.

.DESCRIPTION
    REQ 100.42 / framework REQ 12.17 (owner 2026-10-09: "confirm no ps modules" ... "take that out and rewrite"). The build's
    'keyvault' step used to run the framework's New-PlatformKeyVault.ps1, which needs Az.Accounts + Az.Resources +
    Az.KeyVault and a Connect-AzAccount context -- a second connect path and three modules. This is PIM's own REST port
    of the same contract, authenticated by PIM-Rest's one token client (the step process's certificate identity, or
    the signed-in session):
      1. the resource group (created when missing);
      2. the vault -- reused when it exists (switched to RBAC mode when it is not); a SOFT-DELETED vault of the same
         name is refused with the choices (recover / purge / another name), or hard-purged only with -PurgeSoftDeleted
         (test estates only -- data loss);
      3. 'Key Vault Secrets User' (read) at the vault scope for the bootstrap service principal and/or a managed
         identity -- never 'Secrets Officer' on the bootstrap;
      4. 'Key Vault Secrets Officer' for the identity RUNNING this step (RBAC-mode data-plane rights are not implied by
         Owner), so the later secret upload works.
    Idempotent: every grant is read first and skipped when present.

.OUTPUTS
    PSCustomObject @{ VaultName; VaultUri; ResourceGroup; Location; SubscriptionId; BootstrapAppId; ManagedIdentityObjectId; AuthMethodsGranted }
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)][string]$VaultName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$Location = 'westeurope',
    [Parameter(Mandatory)][string]$SubscriptionId,
    [string]$BootstrapAppId,
    [string]$ManagedIdentityObjectId,
    [switch]$PurgeSoftDeleted,
    [ValidateRange(0, 600)][int]$WaitSeconds = 120
)
$ErrorActionPreference = 'Stop'
$guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
if (-not $BootstrapAppId -and -not $ManagedIdentityObjectId) { throw 'New-PimTenantKeyVault: at least one of -BootstrapAppId or -ManagedIdentityObjectId must be supplied.' }
if ($VaultName -notmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$') { throw "New-PimTenantKeyVault: '$VaultName' is not a Key Vault name." }
if ($SubscriptionId -notmatch $guid) { throw "New-PimTenantKeyVault: -SubscriptionId must be a GUID." }
if ($BootstrapAppId -and $BootstrapAppId -notmatch $guid) { throw "New-PimTenantKeyVault: -BootstrapAppId must be a GUID." }
if ($ManagedIdentityObjectId -and $ManagedIdentityObjectId -notmatch $guid) { throw "New-PimTenantKeyVault: -ManagedIdentityObjectId must be a GUID." }

# The ONE connect path: PIM-Rest (loaded unless the caller already has it -- a test stubs Invoke-PimArm / Invoke-PimGraph).
if (-not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1') }

$kvApi = '2023-07-01'; $rgApi = '2021-04-01'; $raApi = '2022-04-01'
$roleSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'      # Key Vault Secrets User (built-in)
$roleSecretsOfficer = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'   # Key Vault Secrets Officer (built-in)

function Test-PimKvNotFound([object]$ErrorRecord) { return ("$($ErrorRecord.Exception.Message)" -match 'HTTP 404|ResourceNotFound|ResourceGroupNotFound|NotFound') }
function Get-PimKvJwtClaims([string]$Token) {
    try {
        $seg = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json)
    } catch { return $null }
}

# ---- 1. resource group --------------------------------------------------------------------------------------------------
$rgPath = "/subscriptions/$SubscriptionId/resourcegroups/$ResourceGroup"
$rg = $null
try { $rg = Invoke-PimArm -Method GET -Path $rgPath -ApiVersion $rgApi } catch { if (-not (Test-PimKvNotFound $_)) { throw } }
if ($rg) { Write-Host "Using existing RG: $ResourceGroup" }
else {
    Write-Host "Creating resource group: $ResourceGroup ($Location)"
    $rg = Invoke-PimArm -Method PUT -Path $rgPath -ApiVersion $rgApi -Body @{ location = $Location }
}

# ---- 2. the vault ---------------------------------------------------------------------------------------------------------
$kvPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
$kv = $null
try { $kv = Invoke-PimArm -Method GET -Path $kvPath -ApiVersion $kvApi } catch { if (-not (Test-PimKvNotFound $_)) { throw } }
if (-not $kv) {
    # A vault of this name in ANOTHER resource group of the subscription is the same vault (names are global).
    $other = @(Invoke-PimArm -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults" -ApiVersion $kvApi -All | Where-Object { "$($_.name)" -ieq $VaultName }) | Select-Object -First 1
    if ($other) { throw "New-PimTenantKeyVault: vault '$VaultName' already exists in another resource group ($($other.id)) -- use that resource group, or another name." }
}
if (-not $kv) {
    # A soft-deleted vault squatting on the name makes the create fail with VaultAlreadyExists.
    $deleted = @(Invoke-PimArm -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/deletedVaults" -ApiVersion $kvApi -All | Where-Object { "$($_.name)" -ieq $VaultName }) | Select-Object -First 1
    if ($deleted) {
        $dLoc = "$($deleted.properties.location)"
        if ($PurgeSoftDeleted) {
            Write-Warning "Found soft-deleted KV $VaultName in $dLoc. -PurgeSoftDeleted set -- HARD-PURGING (irreversible)."
            [void](Invoke-PimArm -Method POST -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/locations/$dLoc/deletedVaults/$VaultName/purge" -ApiVersion $kvApi)
            $until = [datetime]::UtcNow.AddSeconds($WaitSeconds)
            do {
                Start-Sleep -Seconds 5
                $still = @(Invoke-PimArm -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/deletedVaults" -ApiVersion $kvApi -All | Where-Object { "$($_.name)" -ieq $VaultName })
            } while ($still.Count -and [datetime]::UtcNow -lt $until)
            if ($still.Count) { throw "New-PimTenantKeyVault: the purge of soft-deleted vault '$VaultName' did not complete within $WaitSeconds s -- re-run when it has." }
        } else {
            throw @"
KV $VaultName is in soft-deleted state (location $dLoc). Cannot create a new vault with the same name. Pick one:
  1. Recover the existing vault (preserves any prior secrets): re-create it with createMode 'recover' in the portal
     (Key Vaults > Manage deleted vaults > Recover), then re-run the build.
  2. Hard-purge the soft-deleted vault (DATA LOSS, test estates only): re-run this step with -PurgeSoftDeleted.
  3. Use a different keyVaultName in the build config.
"@
        }
    }
    $tok = Get-PimRestToken -Resource 'arm'
    $tenantId = "$((Get-PimKvJwtClaims -Token $tok).tid)"; $tok = $null
    if ($tenantId -notmatch $guid) { throw 'New-PimTenantKeyVault: could not read the tenant id from the ARM token.' }
    Write-Host "Creating Key Vault: $VaultName (RBAC + soft-delete + purge protection)"
    $body = @{ location = $Location; properties = @{ tenantId = $tenantId; sku = @{ family = 'A'; name = 'standard' }
               enableRbacAuthorization = $true; enableSoftDelete = $true; softDeleteRetentionInDays = 30; enablePurgeProtection = $true } }
    [void](Invoke-PimArm -Method PUT -Path $kvPath -ApiVersion $kvApi -Body $body)
    $until = [datetime]::UtcNow.AddSeconds($WaitSeconds)
    while ($true) {
        try { $kv = Invoke-PimArm -Method GET -Path $kvPath -ApiVersion $kvApi } catch { if (-not (Test-PimKvNotFound $_)) { throw }; $kv = $null }
        $state = "$($kv.properties.provisioningState)"
        if ($kv -and (-not $state -or $state -eq 'Succeeded')) { break }
        if ([datetime]::UtcNow -ge $until) { throw "New-PimTenantKeyVault: vault '$VaultName' did not finish provisioning within $WaitSeconds s (state '$state')." }
        Start-Sleep -Seconds 5
    }
} else {
    Write-Host "Using existing KV: $VaultName"
    if (-not $kv.properties.enableRbacAuthorization) {
        Write-Host "  switching $VaultName to RBAC mode..."
        $kv = Invoke-PimArm -Method PATCH -Path $kvPath -ApiVersion $kvApi -Body @{ properties = @{ enableRbacAuthorization = $true } }
    }
}

# ---- 3. principals to grant read ------------------------------------------------------------------------------------------
$principals = @()
if ($BootstrapAppId) {
    $sp = @(Invoke-PimGraph -Method GET -Path "/servicePrincipals?`$filter=appId eq '$BootstrapAppId'&`$select=id,appId,displayName" -All) | Select-Object -First 1
    if (-not $sp -or -not "$($sp.id)") { throw "New-PimTenantKeyVault: service principal with appId $BootstrapAppId not found in the tenant. Create the bootstrap identity first." }
    $principals += [pscustomobject]@{ ObjectId = "$($sp.id)"; Label = "Bootstrap SPN ($BootstrapAppId)"; Type = 'ServicePrincipal' }
}
if ($ManagedIdentityObjectId) { $principals += [pscustomobject]@{ ObjectId = $ManagedIdentityObjectId; Label = "Managed Identity ($ManagedIdentityObjectId)"; Type = 'ServicePrincipal' } }

function Set-PimKvRoleGrant {
    # Idempotent: the principal's assignments at the vault scope are read first; a present grant is skipped.
    param([string]$Scope, [string]$PrincipalId, [string]$PrincipalType, [string]$RoleId, [string]$RoleName, [string]$Label)
    $defId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$RoleId"
    $have = @(Invoke-PimArm -Method GET -Path "$Scope/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$PrincipalId'" -ApiVersion $raApi -All |
              Where-Object { "$($_.properties.roleDefinitionId)" -match "/roleDefinitions/$RoleId$" })
    if ($have.Count) { Write-Host "$Label already has '$RoleName' on $VaultName -- skipping"; return $false }
    Write-Host "Granting $Label '$RoleName' on $VaultName"
    $b = @{ properties = @{ roleDefinitionId = $defId; principalId = $PrincipalId } }
    if ($PrincipalType) { $b.properties['principalType'] = $PrincipalType }
    [void](Invoke-PimArm -Method PUT -Path "$Scope/providers/Microsoft.Authorization/roleAssignments/$([guid]::NewGuid().ToString())" -ApiVersion $raApi -Body $b)
    return $true
}
$kvScope = $kvPath
foreach ($p in $principals) { [void](Set-PimKvRoleGrant -Scope $kvScope -PrincipalId $p.ObjectId -PrincipalType $p.Type -RoleId $roleSecretsUser -RoleName 'Key Vault Secrets User' -Label $p.Label) }

# ---- 4. the identity running this step: Secrets Officer (RBAC-mode data plane is not implied by Owner) ---------------------
$c = Get-PimKvJwtClaims -Token (Get-PimRestToken -Resource 'arm')
$opId = "$($c.oid)"
$opType = if ("$($c.idtyp)" -eq 'app' -or (-not $c.upn -and -not $c.unique_name -and "$($c.idtyp)" -ne 'user')) { 'ServicePrincipal' } else { 'User' }
$opLabel = if ($c.upn) { "$($c.upn)" } elseif ($c.appid) { "app $($c.appid)" } else { $opId }
if ($opId -match $guid) {
    if (Set-PimKvRoleGrant -Scope $kvScope -PrincipalId $opId -PrincipalType $opType -RoleId $roleSecretsOfficer -RoleName 'Key Vault Secrets Officer' -Label "Operator ($opLabel)") {
        Write-Host '  waiting 10s for RBAC propagation before the secret upload...'
        Start-Sleep -Seconds 10
    }
} else {
    Write-Warning "New-PimTenantKeyVault: could not read the running identity's object id from its token. Grant 'Key Vault Secrets Officer' on $VaultName by hand before the secret upload."
}

$grantedAuth = @()
if ($BootstrapAppId) { $grantedAuth += 'Certificate' }
if ($ManagedIdentityObjectId) { $grantedAuth += 'ManagedIdentity' }
[pscustomobject]@{
    VaultName               = $VaultName
    VaultUri                = "$($kv.properties.vaultUri)"
    ResourceGroup           = $ResourceGroup
    Location                = $Location
    SubscriptionId          = $SubscriptionId
    BootstrapAppId          = $BootstrapAppId
    ManagedIdentityObjectId = $ManagedIdentityObjectId
    AuthMethodsGranted      = $grantedAuth
}
