#Requires -Version 7.0

<#
.SYNOPSIS
  Put the SMTP relay password of a PIM Manager environment into its Key Vault, and let the environment's ENGINE job
  identity read that one secret. A PERSON does not use this script: a SuperAdmin sets the password in PIM Manager >
  Settings > Mail & alerting > SMTP relay > Set relay password (no Key Vault or SQL right). This script is for the Invardia
  Support app (-SqlServerFqdn, sealed) and the fallback. -WhatIf shows every change first and asks for no password.

.DESCRIPTION
  Owner 2026-10-08: "remember i need to have 2 options: shared mailbox or smtp relay solution" / "we dont use certificates
  here, either interactive login or secret". In SMTP relay mode the ENGINE job sends through the relay with a user name
  and a password. 🔒 The password is NEVER in SQL, in the page or in a log: it is a secret in the environment's own Key
  Vault, read at send time by the engine job's managed identity ONLY. 🔒 SECURE-WEB-1 (PIM 3.1.26) / MAIL-WEB-RIGHTS-1:
  PIM Manager's web app sends no mail and holds no Key Vault right -- it never writes or reads this secret, and this
  script never grants its identity anything.

  FOR A PERSON (PIM Manager 3.1.56 or later): PIM Manager > Settings > Mail & alerting > SMTP relay > Set relay password
  (SuperAdmin). The page seals the password to this installation; its updater writes it into Key Vault. No Key Vault right,
  no SQL right, no script.

  THE SEALED HAND-OVER BY THE INVARDIA SUPPORT APP (-SqlServerFqdn with -AdminAppId + -AdminSecret; 3.1.56 or later): a
  browser sign-in is refused on this path (a person uses the page). The installation's updater publishes a public key
  (pim.Settings 'SecretHandoverPublicKey'; its private key stays a secret in the installation's own vault). This script
  seals the password to that key (RSA-OAEP-256 + AES-256-GCM; the vault, the secret name and the key id are bound into the
  seal) and stores ONLY the sealed copy in pim.Settings 'SecretHandoverPending' -- the same sealing the page uses. On its
  next run (nightly, or Update now) the updater -- the only writer of the installation's secrets -- opens it, writes the
  secret, reads it back, deletes the sealed copy and records the result (pim.Settings 'SecretHandoverResult', names
  only). A changed copy, one sealed to another key or for another vault is refused and removed; a failed write keeps the
  old secret. The updater never assigns a role: it reports whether the engine identity (-ManagedIdentityObjectId) may read
  the secret. The vault must be the installation's own vault (the one the updater publishes its key for).

  THE DIRECT PATH (no -SqlServerFqdn) is the documented FALLBACK only, for an installation whose updater is older than
  3.1.56 (it has published no hand-over key), or for a vault that is not the installation's own. Whoever runs it:

    1. finds the vault in -SubscriptionId (or, with -CreateVault + -ResourceGroup, creates it: Azure RBAC authorisation);
    2. writes the secret (-SecretName, default PIM-SmtpRelayPassword). The person running it must ALREADY hold 'Key Vault
       Secrets Officer' on that vault: the script never grants it (a refusal stops and names that step);
    3. grants -ManagedIdentityObjectId (the ENGINE job's identity) 'Key Vault Secrets User' on THAT SECRET only -- never
       the whole vault. With -ManagerAppName (+ -ResourceGroup) the web app's identities are read and REFUSED if given;
    4. reads the secret back and compares it (the value is never printed).

  Sign-in: in the BROWSER by default (Edge, auth code + PKCE, no device code, no module), or the Invardia Support app
  (-AdminAppId + -AdminSecret). No certificate. The password comes from -Password (a SecureString) or a prompt (typed
  twice) -- never as plain text on the command line. -WhatIf signs in, reads and prints every change it would make
  ("What if: ..."), asks for no password and writes nothing (no secret, no role assignment, no vault, no -OutFile).
  Published standalone at https://invardia.com/support/pim/Set-PimSmtpRelayPassword.ps1 (Build-PimSupportScripts.ps1).

.EXAMPLE
  .\Set-PimSmtpRelayPassword.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -VaultName <vault> `
      -ManagedIdentityObjectId <engine job identity object id> -SqlServerFqdn <server>.database.windows.net `
      -AdminAppId <Support app id> -AdminSecret <Support app secret> -WhatIf
  The Invardia Support app's sealed hand-over: preview; then the same command without -WhatIf (it asks for the password
  twice). The installation's updater writes it into the vault on its next run.

.EXAMPLE
  .\Set-PimSmtpRelayPassword.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -VaultName <vault> `
      -ManagedIdentityObjectId <engine job identity object id> -WhatIf
  The direct path (fallback). Preview; then the same command without -WhatIf (it asks for the password twice). Only the engine job's identity:
  PIM Manager's web app never reads the password.

.NOTES
  Requirements:
    PowerShell: 7.0 or later (pwsh). Windows PowerShell 5.1 is not supported.
    Role: a person: none here -- PIM Manager SuperAdmin, Settings > Mail & alerting > Set relay password. Sealed hand-over
          (-SqlServerFqdn): the Invardia Support app only, with its access to the store -- no Key Vault or Azure role.
          Direct path (fallback):Key Vault Secrets Officer and User Access Administrator (or Owner) on the environment's
          Key Vault; Reader on the subscription; Contributor on the resource group only with -CreateVault (Azure).
    Hosts: login.microsoftonline.com, management.azure.com, *.vault.azure.net, *.database.windows.net

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
    # Optional guard (MAIL-WEB-RIGHTS-1): PIM Manager's web container app (e.g. ca-pim-manager) in -ResourceGroup. Its
    # identities are read (Reader) and refused from -ManagedIdentityObjectId -- the web app never reads this secret.
    [string]$ManagerAppName,
    [string]$AdminAppId,
    [string]$AdminSecret,
    # The sealed hand-over: the environment's SQL server. Given = the password is SEALED to the
    # installation and its updater writes it (no Key Vault right); not given = the direct path (the fallback).
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
# Published as ONE standalone file (Build-PimSupportScripts.ps1 inlines every helper below); the next line makes the build
# leave out the optional loads the engine libraries end with and fail on any load left.
# BUILD-NO-OPTIONAL-LOADS
. (Join-Path $PSScriptRoot '_PimMailSetup.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SecretHandover.ps1')   # the sealed hand-over (SECRETS-WRITE)
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

$sealedMode = [bool]"$SqlServerFqdn".Trim()
if ($sealedMode -and "$SqlServerFqdn".Trim() -notmatch '^[A-Za-z0-9.-]+$') { throw "Set-PimSmtpRelayPassword: not a SQL server name: $SqlServerFqdn" }
$result = [ordered]@{ ok = $false; vault = $VaultName; secretName = $SecretName; mode = $(if ($sealedMode) { 'sealed' } else { 'direct' }); vaultCreated = $false; secretWritten = $false; readBack = $false; sealedWritten = $false; grants = @(); reason = '' }
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

# --- SECRETS-WRITE (framework 12.25, decision Q2 a): THE SEALED HAND-OVER -- no Key Vault call, no Key Vault role -------
# This branch reaches only the sign-in and the store (pim.Settings): it writes the SEALED copy and exits. The installation's
# updater writes the secret (engine/_shared/PIM-SecretHandover.ps1 Invoke-PimShoUpdaterStep).
if ($sealedMode) {
    # a PERSON never takes this path (it would need the SQL admin right NO-PERSON-DB-ADMIN removes): the page does it
    if ($authPlan.mode -ne 'secret') { Fail "-SqlServerFqdn is the Invardia Support app's path (-AdminAppId + -AdminSecret). A person sets the relay password in PIM Manager > Settings > Mail & alerting > SMTP relay > Set relay password (SuperAdmin) -- no Key Vault or SQL right needed" }
    Step "[sealed] the installation's hand-over key (pim.Settings $(Get-PimShoPublicKeySetting)) on $SqlServerFqdn"
    $shoCs = ''
    try {
        $global:PIM_SqlServer = "$SqlServerFqdn".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim(); $global:PIM_TenantId = $TenantId
        $global:PIM_ClientId = $null; $global:PIM_SqlClientId = $null; $global:PIM_CertThumbprint = $null; $global:PIM_SqlCertThumbprint = $null
        $global:PIM_ClientSecret = $null; $global:PIM_SqlClientSecret = $null
        $global:PIM_UseManagedIdentity = $false; $global:PIM_NoManagedIdentity = $true   # never this machine's identity
        $global:PIM_SqlAccessToken = Get-Tok 'sql'
        $shoCs = Get-PimSqlConnectionString -Server $global:PIM_SqlServer -Database $global:PIM_SqlDatabase
    } catch { Fail "could not sign in to the store $SqlServerFqdn : $(ErrText $_)" }
    $shoGet = { param($n) Get-PimSqlSettingRaw -ConnectionString $shoCs -Name $n }
    $shoSet = { param($n, $j) Set-PimSqlSetting -ConnectionString $shoCs -Name $n -ValueJson $j }
    $shoReader = "$(@($miIds) | Select-Object -First 1)"
    $shoFallback = 'The fallback: the same command without -SqlServerFqdn (it needs Key Vault Secrets Officer on the vault).'
    if ($WhatIfPreference) {
        $plan = $null
        try { $plan = Invoke-PimShoSubmit -GetSetting $shoGet -SetSetting $shoSet -Kind 'smtp-relay-password' -VaultName $VaultName -SecretName $SecretName -Reader $shoReader -PlanOnly }
        catch { Fail "the store could not be read: $(ErrText $_)" }
        if (-not $plan.ok) { Fail "$($plan.reason). $shoFallback" }
        [void]$PSCmdlet.ShouldProcess("pim.Settings $(Get-PimShoPendingSetting) on $SqlServerFqdn", "store the SMTP relay password SEALED to the installation's key $($plan.keyId)$(if ($plan.replaced) { ' (replaces a hand-over still waiting)' }) -- its updater writes it into $VaultName/$SecretName on its next run; no Key Vault call from here")
        $result.ok = $true; Done; exit 0
    }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $sub = $null
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        try { $sub = Invoke-PimShoSubmit -GetSetting $shoGet -SetSetting $shoSet -Kind 'smtp-relay-password' -VaultName $VaultName -SecretName $SecretName -Value $plain -Reader $shoReader -By (Get-PimMsSignedInUpn) }
        catch { $sub = @{ ok = $false; reason = "the store refused: $((ErrText $_).Replace($plain, '***'))" } }
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $plain = $null }
    if (-not $sub.ok) { Fail "$($sub.reason). $shoFallback" }
    $result.sealedWritten = $true; $result.ok = $true; Done
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host ' SMTP RELAY PASSWORD HANDED OVER (SEALED)' -ForegroundColor Green
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host "  sealed to : the installation's key $($sub.keyId) (the value was not printed and is not stored in the clear)"
    Write-Host "  written by: the installation's updater, on its next run, into $VaultName / $SecretName"
    Write-Host "  result    : pim.Settings $(Get-PimShoResultSetting) (names only); the sealed copy is deleted once written"
    Write-Host '  NEXT      : Update now in PIM Manager (or wait for the nightly run), then Settings > Mail & alerting > Send a test mail.'
    exit 0
}

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
        # SEC-03 (Invardia 2026-11-07): purge protection like every PIM vault; a PRIVATE install's updater gives it the private shape on its next run (rule 11, step 2g-bis)
        $body = @{ location = "$($rg.location)"; properties = @{ tenantId = $TenantId; sku = @{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true; enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true } }
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

# --- SECURE-WEB-1 / MAIL-WEB-RIGHTS-1: the web app's identity never reads the relay password ---------------------------
if ("$ManagerAppName".Trim()) {
    if (-not "$ResourceGroup".Trim()) { Note "-ManagerAppName needs -ResourceGroup (where the web app runs) -- the identities given are not checked against it." 'DarkYellow' }
    else {
        $webApp = $null
        try { $webApp = Arm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerAppName`?api-version=2024-03-01" }
        catch { Note "the Manager app '$ManagerAppName' could not be read, so the identities given are not checked against it: $(ErrText $_)" 'DarkYellow' }
        if ($webApp) {
            $webSel = Select-PimMailNonWebIdentityIds -ObjectIds $miIds -WebObjectIds (Get-PimAppManagedIdentityObjectIds -App $webApp)
            foreach ($l in @($webSel.lines)) { Note $l 'Yellow' }
            $miIds = @($webSel.ids)
            if (@($webSel.refused).Count -and -not $miIds.Count) { Fail "the only identity given is PIM Manager's web app identity, which never reads the relay password -- pass the ENGINE job's identity (-ManagedIdentityObjectId <engine job identity object id>)" }
        }
    }
}

if ($WhatIfPreference) {
    # PowerShell's own "What if:" line for every change the run would make (ShouldProcess answers $false under -WhatIf).
    [void]$PSCmdlet.ShouldProcess("Key Vault $VaultName, secret $SecretName", 'write the SMTP relay password (Key Vault data plane; the value is never printed)')
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
    # SECRETS-WRITE §12.25 / SEC-10 (decided 2026-11-20, option c): the script NEVER grants the writer a Key Vault right. The
    # person running it must already hold 'Key Vault Secrets Officer' on this vault (or run it through the Invardia Support
    # app); a refusal stops with that plain step. (Next: a sealed hand-over the updater writes -- option a.)
    try { [void](Kv -Method PUT -Name $SecretName -Body $writeBody) }
    catch {
        $t = (ErrText $_).Replace($plain, '***')
        if ($t -match '(?i)\b403\b|Forbidden') { Fail "Key Vault refused the write: you need 'Key Vault Secrets Officer' on the vault $VaultName (this script never grants it to you). Ask an Owner to give it to you for this step, or run it through Invardia support. ($t)" }
        Fail "Key Vault refused the write: $t"
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
Step "[3] 'Key Vault Secrets User' on $SecretName (the secret only) for the engine job's identity"
if (-not $miIds.Count) { Note "no -ManagedIdentityObjectId given: nobody was granted read access -- the engine cannot send until its identity may read the secret." 'Yellow' }
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
