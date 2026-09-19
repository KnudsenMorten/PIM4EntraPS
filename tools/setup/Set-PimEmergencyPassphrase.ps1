#Requires -Version 5.1
<#
.SYNOPSIS
  REQ-F -- provision the EMERGENCY OVERRIDE passphrase for one environment, so break-glass can actually be activated.

.DESCRIPTION
  The Manager's Settings -> Emergency override (break-glass) checks the operator's passphrase against the key vault
  secret PIM-EmergencyPasscode in the vault named by the Manager's PIM_EmergencyVault. Measured 2026-09-19: NO
  Manager had PIM_EmergencyVault and no setup script provisioned the passphrase, so every activation was refused
  ("no emergency passcode configured") -- the feature was unusable everywhere, and nothing said so until an incident.

  This script does the three things that make it work, and reads each one back:
    1. stores the passphrase in the environment's key vault as secret PIM-EmergencyPasscode -- as its SHA-256 HEX,
       which the verifier accepts as-is (Resolve-PimEmergencyExpectedHash), so the CLEAR passphrase is never in the
       vault, never in a command line, never in a log;
    2. grants the Manager's managed identity 'Key Vault Secrets User' on THAT SECRET only (not the whole vault);
    3. sets PIM_EmergencyVault=<vault> on the Manager container app (ARM read-modify-write; a new revision).

  The passphrase comes from -Passphrase (a SecureString) or an interactive prompt (typed twice). It is never
  accepted as plain text on the command line.
  Everything goes through ARM / Key Vault REST (PIM-Rest.ps1): no az CLI call carries a value. Authentication is the
  admin app's CERTIFICATE (-TenantId -AdminAppId -AdminCertThumbprint) or the signed-in az user (-UseSignedInAccount,
  asserted to be a user in the named tenant + subscription) -- like the other setup scripts. -WhatIf reads and plans,
  and writes nothing. Run it once per environment, ring 1 first. The key vault must use Azure RBAC authorization.

.PARAMETER SubscriptionId      The environment's subscription (explicit, always).
.PARAMETER ResourceGroup       The resource group of the Manager container app.
.PARAMETER ManagerApp          The Manager container app (default ca-pim-manager).
.PARAMETER ContainerName       The Manager's container, when the app has more than one.
.PARAMETER VaultName           The environment's own key vault.
.PARAMETER VaultResourceGroup  The vault's resource group (default: -ResourceGroup).
.PARAMETER Passphrase          The passphrase, as a SecureString. Omit it to be prompted.

.EXAMPLE
  pwsh -File Set-PimEmergencyPassphrase.ps1 -SubscriptionId <sub> -ResourceGroup rg-pim -VaultName kv-pim-x `
       -TenantId <t> -AdminAppId <appid> -AdminCertThumbprint <thumb> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$ContainerName,
    [string]$VaultName,
    [string]$VaultResourceGroup,
    [string]$SecretName = 'PIM-EmergencyPasscode',
    [System.Security.SecureString]$Passphrase,
    [string]$TenantId,
    [string]$AdminAppId,
    [string]$AdminCertThumbprint,
    [switch]$UseSignedInAccount,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-ArmContainerApps.ps1')

# Key Vault Secrets User (built-in role, read secret values).
$script:PimKvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

function ConvertTo-PimEmergencyPassphraseHash {
    <#
      SecureString -> the lower-case SHA-256 hex of its UTF-8 bytes (exactly what the Manager's verifier computes from
      the typed passphrase). The clear text lives only in this function, in a BSTR that is zeroed before returning.
      Refuses a passphrase shorter than 12 characters, or with leading/trailing whitespace (the GUI sends exactly what
      is typed, so a stray space would make the right passphrase fail in an incident).
    #>
    param([Parameter(Mandatory)][System.Security.SecureString]$Passphrase)
    if ($Passphrase.Length -lt 12) { throw 'the passphrase must be at least 12 characters' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($plain -ne $plain.Trim()) { throw 'the passphrase must not start or end with whitespace' }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $hex = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plain))) -replace '-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        $plain = $null
        return $hex
    } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-PimEmergencyKvSecret {
    # Key Vault data plane over REST (token from PIM-Rest: the certificate SPN, or the signed-in user). The test seam.
    param([Parameter(Mandatory)][ValidateSet('GET','PUT')][string]$Method, [Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SecretName, [object]$Body)
    $url = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $VaultName, $SecretName
    if ($Method -eq 'PUT') { return (Invoke-PimRest -Method PUT -Url $url -Body $Body -Resource 'https://vault.azure.net') }
    return (Invoke-PimRest -Method GET -Url $url -Resource 'https://vault.azure.net')
}

function Get-PimManagerAppPrincipalIds {
    # The Manager app's managed identity principal ids (system-assigned and/or user-assigned). PURE over the ARM object.
    param([Parameter(Mandatory)][object]$App)
    $ids = New-Object System.Collections.Generic.List[string]
    $idn = $App.identity
    if ($idn) {
        if ("$($idn.principalId)".Trim()) { $ids.Add("$($idn.principalId)".Trim()) }
        $ua = $idn.userAssignedIdentities
        if ($ua) { foreach ($p in $ua.PSObject.Properties) { if ("$($p.Value.principalId)".Trim() -and -not $ids.Contains("$($p.Value.principalId)".Trim())) { $ids.Add("$($p.Value.principalId)".Trim()) } } }
    }
    return [string[]]$ids.ToArray()
}

function Invoke-PimEmergencyPassphraseSetup {
    <#
      Plan / apply / read back. Returns the outcome; THROWS on any failure. -WhatIfOnly performs only reads.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$ManagerApp,
        [string]$ContainerName,
        [Parameter(Mandatory)][string]$VaultName,
        [string]$VaultResourceGroup,
        [string]$SecretName = 'PIM-EmergencyPasscode',
        [Parameter(Mandatory)][string]$PassphraseHash,
        [switch]$WhatIfOnly
    )
    if ("$PassphraseHash" -notmatch '^[0-9a-f]{64}$') { throw 'internal: the passphrase hash is not a lower-case SHA-256 hex' }
    if (-not "$VaultResourceGroup".Trim()) { $VaultResourceGroup = $ResourceGroup }
    $out = [ordered]@{ ok = $false; whatIf = [bool]$WhatIfOnly; vault = $VaultName; secretName = $SecretName; managerApp = $ManagerApp
                       principalIds = @(); secretWritten = $false; secretVerified = $false; grantsAdded = @(); grantsPresent = @(); envChanged = $false; envVerified = $false; plan = @() }

    # 1. The Manager app and its identity.
    $app = Get-PimAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
    if (-not $app) { throw "container app '$ManagerApp' not found in resource group '$ResourceGroup' (subscription $SubscriptionId)" }
    $pids = @(Get-PimManagerAppPrincipalIds -App $app)
    if (-not $pids.Count) { throw "'$ManagerApp' has no managed identity -- the Manager could not read the vault. Give it a system-assigned identity first." }
    $out.principalIds = $pids

    # 2. The vault: must exist and use Azure RBAC (a per-secret role assignment needs it).
    $vaultId = "/subscriptions/$SubscriptionId/resourceGroups/$VaultResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"
    $vault = Invoke-PimArm -Method GET -Path $vaultId -ApiVersion '2023-07-01'
    if (-not $vault) { throw "key vault '$VaultName' not found in resource group '$VaultResourceGroup'" }
    if (-not [bool]$vault.properties.enableRbacAuthorization) {
        throw "key vault '$VaultName' uses access policies, not Azure RBAC -- this script grants per-secret RBAC only. Switch the vault to RBAC authorization, or grant the Manager's identity 'get' on secrets by hand."
    }
    $secretScope = "$vaultId/secrets/$SecretName"

    # 3. The plan.
    $existing = $null
    try { $existing = Invoke-PimEmergencyKvSecret -Method GET -VaultName $VaultName -SecretName $SecretName } catch { $existing = $null }
    $out.plan += $(if ($existing) { "REPLACE secret $SecretName in $VaultName (a new version; the old passphrase stops working)" } else { "CREATE secret $SecretName in $VaultName" })
    $roleDefId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($script:PimKvSecretsUserRoleId)"
    $assignments = @()
    try { $assignments = @(Invoke-PimArm -Method GET -Path "$vaultId/providers/Microsoft.Authorization/roleAssignments" -ApiVersion '2022-04-01' -All) } catch { $assignments = @() }
    $need = @()
    foreach ($p in $pids) {
        $has = @($assignments | Where-Object {
            "$($_.properties.principalId)" -eq $p -and "$($_.properties.roleDefinitionId)" -match ([regex]::Escape($script:PimKvSecretsUserRoleId) + '$') -and
            ("$($_.properties.scope)" -eq $vaultId -or "$($_.properties.scope)" -eq $secretScope) })
        if ($has.Count) { $out.grantsPresent += $p } else { $need += $p; $out.plan += "GRANT Key Vault Secrets User on secret $SecretName to the Manager identity $p" }
    }
    $curEnv = ''
    foreach ($c in @($app.properties.template.containers)) {
        if ("$ContainerName".Trim() -and "$($c.name)" -ne "$ContainerName".Trim()) { continue }
        foreach ($e in @($c.env)) { if ("$($e.name)" -eq 'PIM_EmergencyVault') { $curEnv = "$($e.value)" } }
    }
    if ($curEnv -ne $VaultName) { $out.plan += "SET PIM_EmergencyVault=$VaultName on $ManagerApp (new revision)" }
    if ($WhatIfOnly) { $out.ok = $true; return [pscustomobject]$out }

    # 4. The secret: the SHA-256 hex, never the passphrase. Read back and compare.
    [void](Invoke-PimEmergencyKvSecret -Method PUT -VaultName $VaultName -SecretName $SecretName -Body @{
        value = $PassphraseHash; contentType = 'sha256-hex of the PIM emergency override passphrase'
        tags = @{ purpose = 'PIM4EntraPS emergency override'; format = 'sha256-hex' } })
    $out.secretWritten = $true
    $back = Invoke-PimEmergencyKvSecret -Method GET -VaultName $VaultName -SecretName $SecretName
    if ("$($back.value)" -ne $PassphraseHash) { throw "read-back mismatch: secret $SecretName in $VaultName does not hold the value that was written" }
    $out.secretVerified = $true

    # 5. The grant, on the SECRET (least privilege). Idempotent: an existing grant is left alone.
    foreach ($p in $need) {
        $name = [guid]::NewGuid().ToString()
        [void](Invoke-PimArm -Method PUT -Path "$secretScope/providers/Microsoft.Authorization/roleAssignments/$name" -ApiVersion '2022-04-01' -Body @{
            properties = @{ roleDefinitionId = $roleDefId; principalId = $p; principalType = 'ServicePrincipal' } })
        $out.grantsAdded += $p
    }
    if ($need.Count) {
        $chk = @(Invoke-PimArm -Method GET -Path "$secretScope/providers/Microsoft.Authorization/roleAssignments" -ApiVersion '2022-04-01' -All)
        foreach ($p in $need) {
            if (-not @($chk | Where-Object { "$($_.properties.principalId)" -eq $p -and "$($_.properties.roleDefinitionId)" -match ([regex]::Escape($script:PimKvSecretsUserRoleId) + '$') }).Count) {
                throw "the Key Vault Secrets User grant for $p is not visible on read-back"
            }
        }
    }

    # 6. PIM_EmergencyVault on the Manager (read-modify-write, read back inside Set-PimAcaAppEnvValue).
    $envRes = Set-PimAcaAppEnvValue -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -VariableName 'PIM_EmergencyVault' -Value $VaultName -ContainerName $ContainerName
    $out.envChanged = [bool]$envRes.changed
    $out.envVerified = ("$($envRes.value)" -eq $VaultName)
    if (-not $out.envVerified) { throw 'PIM_EmergencyVault did not read back as the vault name' }
    $out.ok = $true
    return [pscustomobject]$out
}

# Dot-sourced (the offline test): define the functions, run nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

$result = [ordered]@{ ok = $false; reason = ''; whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Fail($m) { $result.reason = $m; Write-ResultFile; Write-Host "RESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM emergency override passphrase -> key vault + Manager (REQ-F) ===" -ForegroundColor Cyan
foreach ($p in @(@{ n = 'SubscriptionId'; v = $SubscriptionId }, @{ n = 'ResourceGroup'; v = $ResourceGroup }, @{ n = 'VaultName'; v = $VaultName }, @{ n = 'TenantId'; v = $TenantId })) {
    if (-not "$($p.v)".Trim()) { Fail "-$($p.n) is required" }
}

# --- identity ------------------------------------------------------------------------------
if ($UseSignedInAccount) {
    if ("$AdminAppId".Trim() -or "$AdminCertThumbprint".Trim()) { Fail '-UseSignedInAccount cannot be combined with -AdminAppId/-AdminCertThumbprint' }
    . (Join-Path $here '_PimSignedIn.ps1')
    $who = Get-PimSignedInIdentity -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $who.ok) { Fail "$($who.reason)" }
    Set-PimSignedInGlobals -TenantId $TenantId
    Note "identity: signed-in user $($who.userName)" 'DarkGray'
} else {
    if (-not "$AdminAppId".Trim() -or -not "$AdminCertThumbprint".Trim()) { Fail 'supply -AdminAppId with -AdminCertThumbprint (certificate auth), or -UseSignedInAccount' }
    $global:PIM_TenantId       = $TenantId
    $global:PIM_ClientId       = $AdminAppId
    $global:PIM_CertThumbprint = $AdminCertThumbprint
    Note "identity: app $AdminAppId (certificate)" 'DarkGray'
}

# --- the passphrase (SecureString only; typed twice when prompted) ---------------------------
if (-not $Passphrase) {
    $p1 = Read-Host -AsSecureString -Prompt 'Emergency passphrase (min 12 characters)'
    $p2 = Read-Host -AsSecureString -Prompt 'Type it again'
    $h1 = ''; $h2 = ''
    try { $h1 = ConvertTo-PimEmergencyPassphraseHash -Passphrase $p1; $h2 = ConvertTo-PimEmergencyPassphraseHash -Passphrase $p2 } catch { Fail "$($_.Exception.Message)" }
    if ($h1 -ne $h2) { Fail 'the two entries differ -- nothing was written' }
    $hash = $h1
} else {
    try { $hash = ConvertTo-PimEmergencyPassphraseHash -Passphrase $Passphrase } catch { Fail "$($_.Exception.Message)" }
}

$whatIfOnly = [bool]$WhatIfPreference -or -not $PSCmdlet.ShouldProcess("$VaultName/$SecretName + $ManagerApp", 'store the emergency passphrase hash, grant the Manager read access, set PIM_EmergencyVault')
try {
    $r = Invoke-PimEmergencyPassphraseSetup -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ContainerName $ContainerName `
            -VaultName $VaultName -VaultResourceGroup $VaultResourceGroup -SecretName $SecretName -PassphraseHash $hash -WhatIfOnly:$whatIfOnly
} catch { Fail "$($_.Exception.Message)" }
$hash = $null
foreach ($k in $r.PSObject.Properties.Name) { $result[$k] = $r.$k }
foreach ($line in @($r.plan)) { Note $line }
if ($r.whatIf) {
    $result.ok = $true; $result.reason = 'what-if -- nothing written'
    Write-ResultFile; Write-Host 'RESULT: WHAT-IF -- nothing written' -ForegroundColor Yellow; exit 0
}
$result.ok = $true
$result.reason = "passphrase stored (as SHA-256) in $VaultName/$SecretName and read back; Manager identity grant(s): $(@($r.grantsAdded).Count) added, $(@($r.grantsPresent).Count) present; PIM_EmergencyVault $(if ($r.envChanged) { 'set' } else { 'already set' }) on $ManagerApp"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
Write-Host '  NOTE: a new role assignment can take a few minutes to apply. Settings -> Emergency override shows "Passphrase: configured" once the Manager can read it.' -ForegroundColor DarkGray
exit 0
