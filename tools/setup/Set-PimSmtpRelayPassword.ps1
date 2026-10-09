#Requires -Version 5.1

<#
.SYNOPSIS
  Put the SMTP relay password of a PIM Manager environment into its Key Vault, and let the environment's managed
  identities read that one secret. -WhatIf shows every change first and asks for no password.

.DESCRIPTION
  Owner 2026-10-08: "remember i need to have 2 options: shared mailbox or smtp relay solution" / "we dont use certificates
  here, either interactive login or secret". In SMTP relay mode PIM Manager sends through System.Net.Mail with a user name
  and a password. 🔒 The password is NEVER in SQL, in the page or in a log: it is a secret in the environment's own Key
  Vault, read at send time by the environment's managed identities. PIM Manager's Settings > Mail & alerting writes it
  itself when its identity may; otherwise this script does, as a person who may (or as the Invardia Support app):

    1. finds the vault in -SubscriptionId (or, with -CreateVault + -ResourceGroup, creates it: Azure RBAC authorisation);
    2. writes the secret (-SecretName, default PIM-SmtpRelayPassword) -- when Key Vault refuses the writer, it grants the
       writer 'Key Vault Secrets Officer' on THAT VAULT once and retries (the RBAC change can take a few minutes);
    3. grants every -ManagedIdentityObjectId (the Manager's and the engine job's) 'Key Vault Secrets User' on THAT SECRET
       only -- never the whole vault;
    4. reads the secret back and compares it (the value is never printed).

  Sign-in: in the BROWSER by default (Edge, auth code + PKCE, no device code, no module), or the Invardia Support app
  (-AdminAppId + -AdminSecret). No certificate. The password comes from -Password (a SecureString) or a prompt (typed
  twice) -- never as plain text on the command line. -WhatIf signs in, reads and prints every change it would make
  ("What if: ..."), asks for no password and writes nothing (no secret, no role assignment, no vault, no -OutFile).
  Published standalone at https://invardia.com/support/pim/Set-PimSmtpRelayPassword.ps1 (Build-PimSupportScripts.ps1).

.EXAMPLE
  .\Set-PimSmtpRelayPassword.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -VaultName <vault> `
      -ManagedIdentityObjectId <manager identity object id>,<engine job identity object id> -WhatIf
  Preview; then the same command without -WhatIf (it asks for the password twice).

.LINK
  https://invardia.com/docs/pim/scripts/Set-PimSmtpRelayPassword/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$VaultName,
    [string]$SecretName = 'PIM-SmtpRelayPassword',
    [string[]]$ManagedIdentityObjectId = @(),
    [System.Security.SecureString]$Password,
    # Create the vault when it does not exist (Azure RBAC authorisation, standard SKU, the resource group's region).
    [switch]$CreateVault,
    [string]$ResourceGroup,
    [string]$AdminAppId,
    [string]$AdminSecret,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimMailSetup.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Set-PimSmtpRelayPassword'
try {

$authPlan = Resolve-PimMailSetupAuthMode -AdminAppId $AdminAppId -AdminSecret $AdminSecret
if ($authPlan.reason) { throw "Set-PimSmtpRelayPassword: $($authPlan.reason)" }
if ($authPlan.mode -notin @('browser', 'secret')) { throw 'Set-PimSmtpRelayPassword: sign in in the browser (no credential) or pass -AdminAppId + -AdminSecret.' }
if ($authPlan.mode -eq 'browser' -and -not (Test-PimMsInteractiveHost)) { throw 'Set-PimSmtpRelayPassword: this run signs in in the BROWSER, and this session is not interactive -- run it in a PowerShell window, or pass -AdminAppId + -AdminSecret.' }
if ($SecretName -notmatch '^[0-9A-Za-z-]{1,127}$') { throw "Set-PimSmtpRelayPassword: not a Key Vault secret name: $SecretName" }
if ($VaultName -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') { throw "Set-PimSmtpRelayPassword: not a Key Vault name: $VaultName" }
$miIds = @(@($ManagedIdentityObjectId) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($m in $miIds) { if ($m -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Set-PimSmtpRelayPassword: -ManagedIdentityObjectId '$m' is not an object id" } }

$result = [ordered]@{ ok = $false; vault = $VaultName; secretName = $SecretName; vaultCreated = $false; secretWritten = $false; readBack = $false; grants = @(); reason = '' }
function Note($m, $c = 'Gray') { Write-Host "    $m" -ForegroundColor $c }
function Step($m) { Write-Host "`n--- $m ---" -ForegroundColor Cyan }
function Done {
    if (-not "$OutFile".Trim()) { return }
    if ($WhatIfPreference) { Write-Host "What if: would write the result to $OutFile (not written under -WhatIf)"; return }
    try { ($result | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $OutFile -Encoding utf8 } catch { Write-Warning "could not write -OutFile: $($_.Exception.Message)" }
}
function Fail($why) { $result.reason = $why; Done; Write-Host "`nRESULT: FAILED -- $why" -ForegroundColor Red; exit 1 }

function Get-Tok([string]$Resource) {
    # The sign-in is a READ the -WhatIf preview needs: an inherited -WhatIf would stop Start-Process from opening the
    # browser (the run would then wait 5 minutes for nothing). Local to this function only.
    $WhatIfPreference = $false
    if ($authPlan.mode -eq 'secret') { return (Get-PimMsAppToken -TenantId $TenantId -ClientId $AdminAppId -ClientSecret $AdminSecret -Resource $Resource) }
    return (Get-PimMsBrowserToken -Resource $Resource -TenantId $TenantId)
}
function Arm([string]$Method = 'GET', [string]$Path, $Body) {
    $a = @{ Method = $Method; Uri = "https://management.azure.com$Path"; Headers = @{ Authorization = "Bearer $(Get-Tok 'arm')"; 'Content-Type' = 'application/json' } }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 10) }
    Invoke-RestMethod @a
}
function Kv([string]$Method = 'GET', [string]$Name, $Body) {
    $a = @{ Method = $Method; Uri = "https://$VaultName.vault.azure.net/secrets/$Name`?api-version=7.4"; Headers = @{ Authorization = "Bearer $(Get-Tok 'keyvault')"; 'Content-Type' = 'application/json' } }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Depth 4) }
    Invoke-RestMethod @a
}
function ErrText($e) { ("$($e.Exception.Message) $($e.ErrorDetails.Message)" -replace '\s+', ' ').Trim() }

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- SMTP RELAY PASSWORD -> Key Vault $VaultName / $SecretName" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# --- the password, before anything is touched (not under -WhatIf: a preview needs no secret) -----------------------------
if ($WhatIfPreference) { Note 'WhatIf: the password is not asked for -- it is asked (twice) when you run without -WhatIf.' 'DarkYellow' }
elseif (-not $Password) {
    $p1 = Read-Host -AsSecureString 'SMTP relay password'
    $p2 = Read-Host -AsSecureString 'Type it again'
    $b1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1); $b2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
    try { $same = ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($b1) -ceq [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b2)) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b1); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b2) }
    if (-not $same) { Fail 'the two passwords differ -- nothing was changed' }
    $Password = $p1
}
if (-not $WhatIfPreference -and $Password.Length -lt 1) { Fail 'the password is empty -- nothing was changed' }

# --- 1. the vault --------------------------------------------------------------------------------------------------------
Step "[1] Key Vault $VaultName in subscription $SubscriptionId"
try { $list = @((Arm -Path "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01").value) }
catch { Fail "could not list the Key Vaults of subscription $SubscriptionId : $(ErrText $_)" }
$pick = Select-PimKvVault -Vaults $list -Name $VaultName
$vault = $pick.vault
if (-not $vault) {
    if (-not $CreateVault) { Fail "$($pick.reason). Pass -CreateVault -ResourceGroup <resource group> to create it, or name the environment's vault." }
    if (-not "$ResourceGroup".Trim()) { Fail '-CreateVault needs -ResourceGroup (where the vault is created).' }
    try { $rg = Arm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup`?api-version=2021-04-01" } catch { Fail "resource group $ResourceGroup not found: $(ErrText $_)" }
    if ($PSCmdlet.ShouldProcess($VaultName, "create Key Vault in $ResourceGroup ($($rg.location))")) {
        $body = @{ location = "$($rg.location)"; properties = @{ tenantId = $TenantId; sku = @{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true; enableSoftDelete = $true; softDeleteRetentionInDays = 90 } }
        try { [void](Arm -Method PUT -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName`?api-version=2023-07-01" -Body $body) }
        catch { Fail "could not create Key Vault $VaultName : $(ErrText $_)" }
        $deadline = (Get-Date).AddMinutes(3)
        do { Start-Sleep -Seconds 10; try { $vault = Arm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName`?api-version=2023-07-01" } catch { $vault = $null } } while (-not $vault -and (Get-Date) -lt $deadline)
        if (-not $vault) { Fail "Key Vault $VaultName was created but is not readable yet -- re-run in a few minutes" }
        $result.vaultCreated = $true
        Note "created (Azure RBAC authorisation): $($vault.id)" 'Green'
    } else {
        # -WhatIf: the vault does not exist yet; the next steps are previewed against the id it WOULD get.
        $vault = [pscustomobject]@{ id = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$VaultName"; properties = [pscustomobject]@{ enableRbacAuthorization = $true } }
    }
} else { Note "found: $($vault.id)" 'DarkGray' }
if ($vault.properties -and -not $vault.properties.enableRbacAuthorization) { Note 'this vault uses ACCESS POLICIES, not Azure RBAC: the read grants below do not apply -- give the managed identities "Get" on secrets in its access policies.' 'Yellow' }

if ($WhatIfPreference) {
    # PowerShell's own "What if:" line for every change the run would make (ShouldProcess answers $false under -WhatIf).
    [void]$PSCmdlet.ShouldProcess("Key Vault $VaultName, secret $SecretName", 'write the SMTP relay password (Key Vault data plane; the value is never printed)')
    [void]$PSCmdlet.ShouldProcess("Key Vault $VaultName ($($vault.id))", "ONLY IF Key Vault refuses the write: assign Azure role 'Key Vault Secrets Officer' on this vault to the signed-in account")
    $secScope = Get-PimKvSecretScope -VaultId "$($vault.id)" -SecretName $SecretName
    foreach ($oid in $miIds) { [void]$PSCmdlet.ShouldProcess("managed identity $oid", "assign Azure role 'Key Vault Secrets User' on the secret only ($secScope)") }
    if (-not $miIds.Count) { Note 'WhatIf: no -ManagedIdentityObjectId given -- nobody would be granted read access.' 'Yellow' }
    $result.ok = $true; Done; exit 0
}

# --- 2. the secret -------------------------------------------------------------------------------------------------------
Step "[2] write secret $SecretName"
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    $writeBody = @{ value = $plain; contentType = 'PIM Manager SMTP relay password' }
    $written = $false; $granted = $false
    $deadline = (Get-Date).AddMinutes(6)
    while (-not $written) {
        try { [void](Kv -Method PUT -Name $SecretName -Body $writeBody); $written = $true }
        catch {
            $t = (ErrText $_).Replace($plain, '***')
            if ($t -notmatch '(?i)\b403\b|Forbidden') { Fail "Key Vault refused the write: $t" }
            if (-not $granted) {
                # the writer may manage the vault (Owner / User Access Administrator) but not its secrets: grant the data-plane
                # right on THIS vault to the writer itself, once
                $claims = ConvertFrom-PimMsJwtClaims -Token (Get-Tok 'keyvault')
                $me = "$($claims.oid)"; $kind = if ("$($claims.idtyp)" -eq 'app' -or -not "$($claims.upn)$($claims.preferred_username)") { 'ServicePrincipal' } else { 'User' }
                if (-not $me) { Fail "Key Vault refused the write and the signed-in identity could not be read: $t" }
                $req = New-PimKvRoleAssignmentRequest -Scope "$($vault.id)" -SubscriptionId $SubscriptionId -RoleId (Get-PimKvRoleId -Role SecretsOfficer) -PrincipalId $me -PrincipalType $kind
                try { [void](Arm -Method PUT -Path $req.path -Body $req.body); Note "granted 'Key Vault Secrets Officer' on $VaultName to the writer ($me) -- waiting for it to take effect" 'Yellow' }
                catch { $g = ErrText $_; if ($g -notmatch 'RoleAssignmentExists') { Fail "Key Vault refused the write ($t), and the writer could not be given 'Key Vault Secrets Officer' on the vault: $g" } }
                $granted = $true
            }
            if ((Get-Date) -ge $deadline) { Fail 'Key Vault still refuses the write 6 minutes after the grant -- re-run the script; the grant is in place' }
            Start-Sleep -Seconds 20
        }
    }
    $result.secretWritten = $true
    Note 'written' 'Green'
    # --- 4. read back (moved up: the value is still in memory here, and is compared, never printed) ---------------------
    $back = $null
    try { $back = "$((Kv -Name $SecretName).value)" } catch { $back = $null }
    $result.readBack = ($null -ne $back -and $back -ceq $plain)
    if (-not $result.readBack) { Note 'the secret could not be read back to compare (the writer may hold write-only rights) -- it was written' 'Yellow' }
    else { Note 'read back and identical' 'Green' }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $plain = $null; $writeBody = $null; $back = $null
}

# --- 3. who may read it --------------------------------------------------------------------------------------------------
Step "[3] 'Key Vault Secrets User' on $SecretName (the secret only) for the sending identities"
if (-not $miIds.Count) { Note 'no -ManagedIdentityObjectId given: nobody was granted read access -- PIM Manager cannot send until its identities may read the secret.' 'Yellow' }
$scope = Get-PimKvSecretScope -VaultId "$($vault.id)" -SecretName $SecretName
foreach ($oid in $miIds) {
    $req = New-PimKvRoleAssignmentRequest -Scope $scope -SubscriptionId $SubscriptionId -RoleId (Get-PimKvRoleId -Role SecretsUser) -PrincipalId $oid
    try { [void](Arm -Method PUT -Path $req.path -Body $req.body); $result.grants += [ordered]@{ principalId = $oid; state = 'granted' }; Note "granted to $oid" 'Green' }
    catch {
        $g = ErrText $_
        if ($g -match 'RoleAssignmentExists') { $result.grants += [ordered]@{ principalId = $oid; state = 'already' }; Note "already held by $oid" 'DarkGray' }
        else { $result.grants += [ordered]@{ principalId = $oid; state = 'FAILED'; reason = $g }; Fail "could not grant read access on the secret to $oid : $g" }
    }
}

$result.ok = $true
Done
Write-Host ''
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host ' SMTP RELAY PASSWORD READY' -ForegroundColor Green
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host "  vault / secret : $VaultName / $SecretName (the value was not printed)"
Write-Host "  read by        : $(if ($miIds.Count) { $miIds -join ', ' } else { 'nobody yet' })"
Write-Host '  NEXT           : PIM Manager > Settings > Mail & alerting (or Get Started > Mail sender) > SMTP relay: the same'
Write-Host "                   vault and secret name, then Send a test mail. A new grant can take a few minutes to apply."
exit 0
} finally { Stop-PimScriptRun -Script 'Set-PimSmtpRelayPassword' }
