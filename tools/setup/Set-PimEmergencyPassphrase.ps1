#Requires -Version 5.1

<#
.SYNOPSIS
  Sets up the emergency override (break-glass) passphrase of one PIM Manager environment: stores a check of it (a salted, slow PBKDF2-SHA256 hash, never the passphrase) in the environment's PIM database, where the Manager reads it at once; the Manager needs no Key Vault access.

.DESCRIPTION
  REQ-F -- provision the EMERGENCY OVERRIDE passphrase for one environment, so break-glass can actually be activated.
  SECURE-WEB-1 (3.1.26, owner: "the internet-facing identity has NO Key Vault edge"): the Manager is the internet-facing app,
  so its identity holds NO Key Vault role. The passphrase check therefore lives in the PIM database the Manager already reads
  (pim.Settings 'EmergencyPassphraseVerifier'):
    * the passphrase is turned into its SHA-256 hex HERE (the clear text never leaves this window), then into a verifier:
      PBKDF2-HMAC-SHA256 over that hex, 600000 iterations, 16 random bytes of salt of its own (engine\_shared\
      PIM-EmergencyVerifier.ps1). Only the verifier is written -- never the passphrase, never its plain hash;
    * it is READ BACK and checked against the same hash before the script says OK;
    * the change is audited (emergency.passphrase.set);
    * the Manager reads it on every activation -- it works the moment this script finishes, no restart, no engine run.
  Nothing is written in Key Vault, no role is granted, the Manager app is not changed.

  -MigrateFromKeyVault (with -VaultName): an installation set up BEFORE 3.1.26 kept the SHA-256 hex in the key vault secret
  PIM-EmergencyPasscode. This reads that secret ONCE (as you) and stores the verifier derived from it -- it does not ask for
  the passphrase, which stays the same. The update does this by itself where its identity may read the secret.
  The old secret and the Manager identity's old grant on it are NOT removed by this script: the update reports a leftover
  grant (SECURE-WEB-1); remove it, and the secret when you no longer need it.

  The passphrase comes from -Passphrase (a SecureString) or an interactive prompt (typed twice). It is never accepted as
  plain text on the command line. Everything goes through ARM / SQL / Key Vault REST: no command-line tool, no PowerShell
  module. Authentication is the signed-in person (-UseSignedInAccount: the browser sign-in, or the Invardia Support session
  open in this window) or, for automation, an admin app's certificate (-TenantId -AdminAppId -AdminCertThumbprint). The
  identity must be a member of the installation's SQL admin group. -WhatIf reads and plans, and writes nothing.
  SETTINGS-CLARITY (owner 2026-11-10): published standalone at https://invardia.com/support/pim/Set-PimEmergencyPassphrase.ps1
  (Build-PimSupportScripts.ps1); Settings > Emergency access prints the two-line command with the installation's values.

.PARAMETER SubscriptionId      The environment's subscription (explicit, always).
.PARAMETER ResourceGroup       The resource group of the Manager container app.
.PARAMETER ManagerApp          The Manager container app (default ca-pim-manager): its PIM_SqlServer / PIM_SqlDatabase name the database.
.PARAMETER ContainerName       The Manager's container, when the app has more than one.
.PARAMETER SqlServerFqdn       The database server (default: the Manager app's PIM_SqlServer).
.PARAMETER SqlDatabase         The database (default: the Manager app's PIM_SqlDatabase, else PimPlatform).
.PARAMETER VaultName           Only with -MigrateFromKeyVault: the key vault an earlier version kept the passphrase in.
.PARAMETER SecretName          Only with -MigrateFromKeyVault: the secret (default PIM-EmergencyPasscode).
.PARAMETER MigrateFromKeyVault Move the passphrase an earlier version kept in -VaultName into the database (no passphrase asked).
.PARAMETER Passphrase          The passphrase, as a SecureString. Omit it to be prompted.

  -WhatIf asks for no passphrase: it signs in, reads the Manager app and whether a check is already stored, prints the change
  it would make and writes nothing.

.EXAMPLE
  .\Set-PimEmergencyPassphrase.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -ResourceGroup <resource group> -UseSignedInAccount -WhatIf
  Preview; then the same command without -WhatIf (it asks for the passphrase twice).

.EXAMPLE
  .\Set-PimEmergencyPassphrase.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -ResourceGroup <resource group> -VaultName <key vault name> -MigrateFromKeyVault -UseSignedInAccount
  Move the passphrase of an installation set up before 3.1.26 into the database once (it is not asked for).

.NOTES
  Requirements:
    PowerShell: 7.0 or later (pwsh). Windows PowerShell 5.1 is not supported.
    Role: Reader on the PIM Manager's resource group (Azure) and a member of the installation's SQL admin group (database);
          with -MigrateFromKeyVault also Key Vault Secrets User on the old key vault (Azure).
    Hosts: login.microsoftonline.com, management.azure.com, *.database.windows.net, *.vault.azure.net

.LINK
  https://invardia.com/docs/pim/scripts/Set-PimEmergencyPassphrase/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$ContainerName,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase,
    [string]$VaultName,
    [string]$SecretName = 'PIM-EmergencyPasscode',
    [switch]$MigrateFromKeyVault,
    [System.Security.SecureString]$Passphrase,
    [string]$TenantId,
    [string]$AdminAppId,
    [string]$AdminCertThumbprint,
    [switch]$UseSignedInAccount,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
# SETTINGS-CLARITY (2026-11-10): published as ONE file (Build-PimSupportScripts.ps1 inlines every helper loaded below,
# and with the next line leaves no dot-source at all); the published copy's line 1 becomes the PowerShell 7 requirement
# (PS7-REQ) while the repository copy keeps 5.1 for the offline tests.
# BUILD-NO-OPTIONAL-LOADS
# BUILD-PUBLISH-REQUIRES-7
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-ArmContainerApps.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-EmergencyVerifier.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                # -UseSignedInAccount: the Support session, else the browser

function ConvertTo-PimEmergencyPassphraseHash {
    <#
      SecureString -> the lower-case SHA-256 hex of its UTF-8 bytes (the pre-hash the verifier is derived from; exactly what
      the Manager's verifier computes from the typed passphrase). The clear text lives only in this function, in a BSTR that
      is zeroed before returning. Refuses a passphrase shorter than 12 characters, or with leading/trailing whitespace (the
      GUI sends exactly what is typed, so a stray space would make the right passphrase fail in an incident).
    #>
    param([Parameter(Mandatory)][System.Security.SecureString]$Passphrase)
    if ($Passphrase.Length -lt 12) { throw 'the passphrase must be at least 12 characters' }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
    try {
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ($plain -ne $plain.Trim()) { throw 'the passphrase must not start or end with whitespace' }
        $hex = Get-PimEmergencyPreHash -Text $plain
        $plain = $null
        return $hex
    } finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-PimEmergencyKvSecret {
    # Key Vault data plane over REST (token from PIM-Rest: the certificate SPN, or the signed-in user) -- READ ONLY, used by
    # -MigrateFromKeyVault to read the secret an earlier version wrote. The test seam.
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$SecretName)
    $url = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $VaultName, $SecretName
    return (Invoke-PimRest -Method GET -Url $url -Resource 'https://vault.azure.net')
}

function Get-PimManagerAppSqlTarget {
    # The Manager app's PIM_SqlServer / PIM_SqlDatabase (the database it reads). PURE over the ARM object.
    param([Parameter(Mandatory)][object]$App, [string]$ContainerName)
    $srv = ''; $db = ''
    foreach ($c in @($App.properties.template.containers)) {
        if ("$ContainerName".Trim() -and "$($c.name)" -ne "$ContainerName".Trim()) { continue }
        foreach ($e in @($c.env)) {
            if ("$($e.name)" -eq 'PIM_SqlServer' -and "$($e.value)".Trim()) { $srv = "$($e.value)".Trim() }
            if ("$($e.name)" -eq 'PIM_SqlDatabase' -and "$($e.value)".Trim()) { $db = "$($e.value)".Trim() }
        }
    }
    if ($srv -and $srv -notmatch '\.') { $srv = "$srv.database.windows.net" }
    return [pscustomobject]@{ server = $srv; database = $db }
}

function Invoke-PimEmergencyPassphraseSetup {
    <#
      Plan / apply / read back. -Store { param($op = get|set|audit, $name, $value) } is the PIM database (pim.Settings).
      Returns the outcome; THROWS on any failure. -WhatIfOnly performs only reads. Writes ONE setting -- nothing in Key
      Vault, no role assignment, no change to the Manager app.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PassphraseHash,
        [Parameter(Mandatory)][scriptblock]$Store,
        [string]$Source = 'Set-PimEmergencyPassphrase',
        [int]$Iterations = 0,
        [switch]$WhatIfOnly
    )
    if ("$PassphraseHash" -notmatch '^[0-9a-f]{64}$') { throw 'internal: the passphrase hash is not a lower-case SHA-256 hex' }
    $name = Get-PimEmergencyVerifierSettingName
    $out = [ordered]@{ ok = $false; whatIf = [bool]$WhatIfOnly; setting = $name; replaced = $false; written = $false; verified = $false; audited = $false; plan = @() }
    $existing = $null
    try { $existing = & $Store 'get' $name $null } catch { throw "could not read pim.Settings '$name' -- refusing to write over an unread setting: $($_.Exception.Message)" }
    $out.replaced = [bool]($null -ne $existing -and (ConvertFrom-PimEmergencyVerifier -Value $existing).ok)
    $out.plan += $(if ($out.replaced) { "REPLACE the emergency passphrase check in the PIM database (pim.Settings $name; the old passphrase stops working)" } else { "STORE the emergency passphrase check in the PIM database (pim.Settings ${name}: PBKDF2-SHA256, $(Get-PimEmergencyVerifierIterations) iterations, its own salt)" })
    if ($WhatIfOnly) { $out.ok = $true; return [pscustomobject]$out }

    $ver = New-PimEmergencyVerifier -PreHashHex $PassphraseHash -Source $Source -Iterations $Iterations
    [void](& $Store 'set' $name $ver)
    $out.written = $true
    $back = & $Store 'get' $name $null
    if (-not (Test-PimEmergencyVerifier -Verifier $back -PreHashHex $PassphraseHash)) {
        throw "read-back mismatch: pim.Settings '$name' does not hold the check that was written"
    }
    $out.verified = $true
    try {
        [void](& $Store 'audit' $name @{ before = $(if ($out.replaced) { 'a previous check' } else { $null }); after = @{ alg = 'pbkdf2-sha256'; iter = $ver.iter; source = $Source }; action = 'emergency.passphrase.set' })
        $out.audited = $true
    } catch { Write-Warning "audit not written: $($_.Exception.Message)" }
    $out.ok = $true
    return [pscustomobject]$out
}

# Dot-sourced (the offline test): define the functions, run nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

$null = Start-PimScriptRun -Script 'Set-PimEmergencyPassphrase'
try {
$result = [ordered]@{ ok = $false; reason = ''; whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Fail($m) { $result.reason = $m; Write-ResultFile; Write-Host "RESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM emergency override passphrase -> the PIM database (REQ-F, SECURE-WEB-1) ===" -ForegroundColor Cyan
foreach ($p in @(@{ n = 'SubscriptionId'; v = $SubscriptionId }, @{ n = 'ResourceGroup'; v = $ResourceGroup }, @{ n = 'TenantId'; v = $TenantId })) {
    if (-not "$($p.v)".Trim()) { Fail "-$($p.n) is required" }
}
if ($MigrateFromKeyVault -and -not "$VaultName".Trim()) { Fail '-MigrateFromKeyVault needs -VaultName (the key vault the passphrase was kept in)' }
if ($MigrateFromKeyVault -and $Passphrase) { Fail '-MigrateFromKeyVault moves the passphrase that is already set -- do not give -Passphrase with it' }

# --- identity ------------------------------------------------------------------------------
if ($UseSignedInAccount) {
    if ("$AdminAppId".Trim() -or "$AdminCertThumbprint".Trim()) { Fail '-UseSignedInAccount cannot be combined with -AdminAppId/-AdminCertThumbprint' }
    $who = Get-PimSignedInIdentity -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $who.ok) { Fail "$($who.reason)" }
    Set-PimSignedInGlobals -TenantId $TenantId
    Note "identity: signed-in user $($who.userName)" 'DarkGray'
} else {
    if (-not "$AdminAppId".Trim() -or -not "$AdminCertThumbprint".Trim()) { Fail 'supply -AdminAppId with -AdminCertThumbprint (certificate auth), or -UseSignedInAccount' }
    $global:PIM_TenantId       = $TenantId
    $global:PIM_ClientId       = $AdminAppId
    $global:PIM_CertThumbprint = $AdminCertThumbprint
    $global:PIM_ClientSecret   = $null
    Note "identity: app $AdminAppId (certificate)" 'DarkGray'
}

# --- the database: named by the Manager app unless given ------------------------------------
if (-not "$SqlServerFqdn".Trim() -or -not "$SqlDatabase".Trim()) {
    $app = $null
    try { $app = Get-PimAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp } catch { Fail "could not read the container app '$ManagerApp': $($_.Exception.Message)" }
    if (-not $app) { Fail "container app '$ManagerApp' not found in resource group '$ResourceGroup' (subscription $SubscriptionId)" }
    $tgt = Get-PimManagerAppSqlTarget -App $app -ContainerName $ContainerName
    if (-not "$SqlServerFqdn".Trim()) { $SqlServerFqdn = $tgt.server }
    if (-not "$SqlDatabase".Trim()) { $SqlDatabase = $(if ($tgt.database) { $tgt.database } else { 'PimPlatform' }) }
}
if (-not "$SqlServerFqdn".Trim()) { Fail "the Manager app '$ManagerApp' names no database server (PIM_SqlServer) -- give -SqlServerFqdn" }
$global:PIM_SqlServer = "$SqlServerFqdn".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()
if ($UseSignedInAccount) {
    try { $sqlWho = Connect-PimSignedInSql -TenantId $TenantId; Note "database identity: signed-in user $($sqlWho.userName)" 'DarkGray' } catch { Fail "$($_.Exception.Message)" }
} else { $global:PIM_SqlClientId = $AdminAppId; $global:PIM_SqlCertThumbprint = $AdminCertThumbprint }
$cs = ''
try { $cs = Get-PimSqlConnectionString -Server $global:PIM_SqlServer -Database $global:PIM_SqlDatabase } catch { Fail "could not build a connection string: $($_.Exception.Message)" }
Note "database: $($global:PIM_SqlServer)/$($global:PIM_SqlDatabase)" 'DarkGray'
$store = {
    param($op, $name, $value)
    switch ($op) {
        'get'   { return (Get-PimSqlSetting -ConnectionString $cs -Name $name) }
        'set'   { Set-PimSqlSetting -ConnectionString $cs -Name $name -Value $value; return $null }
        'audit' { Write-PimSqlAuditEvent -ConnectionString $cs -Actor "$(if ($UseSignedInAccount) { $who.userName } else { "app:$AdminAppId" })" -ActorSource 'setup' -Action "$($value.action)" -Target $name -Before $value.before -After $value.after; return $null }
    }
}

# --- the pre-hash: the passphrase (SecureString only; typed twice when prompted), or the old Key Vault secret ---------
$source = 'Set-PimEmergencyPassphrase'
if ($MigrateFromKeyVault) {
    $sec = $null
    try { $sec = Invoke-PimEmergencyKvSecret -VaultName "$VaultName".Trim() -SecretName "$SecretName".Trim() } catch { Fail "could not read secret $SecretName in key vault $VaultName (you need Key Vault Secrets User on it): $($_.Exception.Message)" }
    $hash = ConvertTo-PimEmergencyPreHashFromSecret -SecretValue $(if ($sec) { $sec.value } else { '' })
    if (-not $hash) { Fail "secret $SecretName in key vault $VaultName is empty -- nothing to move; run without -MigrateFromKeyVault to set a new passphrase" }
    $source = "Set-PimEmergencyPassphrase -MigrateFromKeyVault ($VaultName)"
    Note "the passphrase kept in key vault $VaultName is moved (it is not asked for and does not change)" 'DarkGray'
} elseif ($WhatIfPreference -and -not $Passphrase) {
    # 12.7: -WhatIf writes nothing, so it needs no passphrase -- a placeholder hash plans the same steps.
    Note 'What if: no passphrase is asked for -- nothing will be stored' 'Yellow'
    $hash = '0' * 64
} elseif (-not $Passphrase) {
    $p1 = Read-Host -AsSecureString -Prompt 'Emergency passphrase (min 12 characters)'
    $p2 = Read-Host -AsSecureString -Prompt 'Type it again'
    $h1 = ''; $h2 = ''
    try { $h1 = ConvertTo-PimEmergencyPassphraseHash -Passphrase $p1; $h2 = ConvertTo-PimEmergencyPassphraseHash -Passphrase $p2 } catch { Fail "$($_.Exception.Message)" }
    if ($h1 -ne $h2) { Fail 'the two entries differ -- nothing was written' }
    $hash = $h1
} else {
    try { $hash = ConvertTo-PimEmergencyPassphraseHash -Passphrase $Passphrase } catch { Fail "$($_.Exception.Message)" }
}

$whatIfOnly = -not $PSCmdlet.ShouldProcess("the PIM database $($global:PIM_SqlServer)/$($global:PIM_SqlDatabase) (pim.Settings $(Get-PimEmergencyVerifierSettingName))", "store the emergency passphrase check (PBKDF2-SHA256, its own salt)")
try {
    $r = Invoke-PimEmergencyPassphraseSetup -PassphraseHash $hash -Store $store -Source $source -WhatIfOnly:$whatIfOnly
} catch { Fail "$($_.Exception.Message)" }
$hash = $null
foreach ($k in $r.PSObject.Properties.Name) { $result[$k] = $r.$k }
foreach ($line in @($r.plan)) { if ($r.whatIf) { Note "What if: would $line" 'Yellow' } else { Note $line } }
if ($r.whatIf) {
    $result.ok = $true; $result.reason = 'what-if -- nothing written'
    Write-ResultFile; Write-Host 'RESULT: WHAT-IF -- nothing written' -ForegroundColor Yellow; exit 0
}
$result.ok = $true
$result.reason = "emergency passphrase check $(if ($r.replaced) { 'replaced' } else { 'stored' }) in the PIM database and read back$(if ($MigrateFromKeyVault) { " (moved from key vault $VaultName)" }); it works at once"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
if ($MigrateFromKeyVault) { Write-Host "  NOTE: the secret $SecretName in $VaultName is no longer read by PIM Manager. Remove the Manager identity's role on it (the update reports it until then), and the secret when you no longer need it." -ForegroundColor DarkGray }
exit 0
} finally { Stop-PimScriptRun -Script 'Set-PimEmergencyPassphrase' }
