#requires -Version 5.1
<#
.SYNOPSIS
    Leave a usable `az` context for ONE estate tenant, authenticating through the estate's own
    chain: bootstrap certificate -> that tenant's Key Vault -> its Modern SPN. Designed to be the
    `-PreAuthScript` of an unattended scheduled task.

.DESCRIPTION
    🔴 WHY THIS EXISTS. A scheduled task does not inherit your `az` login, and the daily platform
    update needs one PER TENANT because every tenant in an MSP estate is a different subscription.
    Measured 2026-09-03: the armed update ran against whatever context was ambient and failed as

        ERROR: The resource 'acrpimwa678' ... could not be found in subscription
               '<operator-subscription>'

    -- which names a missing RESOURCE and reads as "the registry is gone", when the registry was
    fine and the context was wrong. After the abort guard was added it failed honestly instead:

        ABORT: az context is '<operator-sub>', expected '<customer-sub>'

    🪤 THE UNDERLYING TRAP, which is why asserting is not optional: `az account set --subscription
    <id>` is SILENT when that subscription is not visible to the current login. It does not error;
    it leaves you exactly where you were. Every command afterwards then runs somewhere plausible
    and wrong.

    THE CHAIN, and why each hop exists:
      1. the BOOTSTRAP SPN + certificate (mgmt1 LocalMachine\My, thumbprint from the tenant's
         bootstrap/platform-config.json) -- the only identity known before reading anything;
      2. that tenant's OWN Key Vault -> Modern-AppId / Modern-Secret;
      3. `az login --service-principal` as the Modern SPN, which is the identity that actually
         holds ARM rights in that tenant.
      🪤 Do NOT try to shortcut to step 3 with the bootstrap SPN: it is Key Vault data-plane only,
      has NO ARM rights, and `Get-Az*` returns EMPTY rather than erroring -- so the subscription
      looks empty instead of forbidden.

.PARAMETER TenantShortName
    Estate short name, e.g. 'test1mspmstintctrr2wa678'.

.PARAMETER AzureConfigDir
    Isolate the az profile so an unattended task cannot disturb the machine-wide default context
    (a concurrent session on this host relies on it). Strongly recommended.

.EXAMPLE
    # as a scheduled-task pre-auth hook
    ./Connect-PimTenantAz.ps1 -TenantShortName test1mspmstintctrr2wa678 `
        -AzureConfigDir C:\ProgramData\pim\az-wa678
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantShortName,
    [string]$EstateRoot = 'C:\AutomateIT-TestRepo',
    [string]$AzureConfigDir,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
function Say($m){ if (-not $Quiet) { Write-Host "    $m" -ForegroundColor DarkGray } }

if ("$AzureConfigDir".Trim()) {
    $null = New-Item -ItemType Directory -Force -Path $AzureConfigDir -ErrorAction SilentlyContinue
    $env:AZURE_CONFIG_DIR = $AzureConfigDir
    Say "az profile: $AzureConfigDir (isolated -- the machine-wide default context is untouched)"
}

# 🔴 A FRESH az PROFILE HAS NO EXTENSIONS, AND az ASKS BEFORE INSTALLING ONE:
#     The command requires the extension containerapp. Do you want to install it now? (Y/n):
# With no stdin -- which is every scheduled task -- that prompt is never answered and the process
# HANGS. Measured 2026-09-03: the daily update sat at exactly this point for 30+ minutes, having
# written one line to its transcript, until its 1-hour task limit would have killed it. The task
# state said "running" the whole time, so from outside it looked like slow work rather than a
# deadlock, and it would have done that EVERY NIGHT.
# 🪤 This is a property of the ISOLATED profile, not of the machine: the interactive profile on
# this host already has the extension, so it never reproduces when you run the same command by
# hand. Isolating the profile is still right -- it stops an unattended job disturbing the shared
# default context -- but the isolation has to carry this with it.
az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>&1 | Out-Null
az config set extension.dynamic_install_allow_preview=true      --only-show-errors 2>&1 | Out-Null
Say 'az extensions: dynamic install enabled WITHOUT prompt (an unattended run cannot answer one)'

$cfgPath = Join-Path $EstateRoot "$TenantShortName\bootstrap\platform-config.json"
if (-not (Test-Path -LiteralPath $cfgPath)) { throw "no bootstrap config for '$TenantShortName' at $cfgPath" }
$cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json

# 1) bootstrap cert -> Key Vault
Connect-AzAccount -ServicePrincipal -Tenant $cfg.TenantId -ApplicationId $cfg.BootstrapAppId `
    -CertificateThumbprint $cfg.BootstrapThumbprint -Subscription $cfg.SubscriptionId `
    -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
Say "bootstrap SPN connected (tenant $($cfg.TenantId))"

# 2) the tenant's own Modern SPN
$appId  = Get-AzKeyVaultSecret -VaultName $cfg.KeyVaultName -Name 'Modern-AppId'  -AsPlainText -ErrorAction Stop
$secret = Get-AzKeyVaultSecret -VaultName $cfg.KeyVaultName -Name 'Modern-Secret' -AsPlainText -ErrorAction Stop
if (-not "$appId".Trim())  { throw "Modern-AppId is empty in $($cfg.KeyVaultName)." }
if (-not "$secret".Trim()) { throw "Modern-Secret is empty in $($cfg.KeyVaultName) -- az CLI cert auth needs an exported PEM, so the secret is what this path uses." }
Say "modern SPN: $appId (from $($cfg.KeyVaultName))"

# 3) az login as that SPN, then ASSERT
az login --service-principal -u $appId -p $secret --tenant $cfg.TenantId --only-show-errors -o none 2>&1 | Out-Null
az account set --subscription $cfg.SubscriptionId --only-show-errors 2>&1 | Out-Null
$ctx = (az account show --query id -o tsv 2>$null)
if ("$ctx".Trim() -ne "$($cfg.SubscriptionId)".Trim()) {
    throw "az context is '$ctx' after login, expected '$($cfg.SubscriptionId)'. The login did not take -- do not proceed."
}
Say "az context asserted: $ctx"
[pscustomobject]@{ TenantId = $cfg.TenantId; SubscriptionId = $cfg.SubscriptionId; AppId = $appId }
