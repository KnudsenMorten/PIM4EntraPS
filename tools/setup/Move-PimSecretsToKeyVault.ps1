#Requires -Version 5.1

<#
.SYNOPSIS
  Moves the secrets of one PIM Manager install that are not Key Vault references -- Container Apps secrets stored as values and plain container settings that hold a secret -- into the install's own Key Vault, and switches each app and job to a Key Vault reference read with its own identity.

.DESCRIPTION
  SEC-10 mover (framework 4 "secrets in Key Vault only"; the setup step 'keyvault-secrets-only' reports what this moves).
  Without -Apply (or with -WhatIf) the script only PLANS, read-only, and prints names only: each secret -> its vault secret
  name, each role assignment to add, each app / job secret switched to keyVaultUrl + identity, and what the switch does
  (the Manager app gets a new revision; a job's change applies to its next execution).

  With -Apply, per install, each step read back before the next:
    1. 'Key Vault Secrets User' for the identity that reads the reference (the app's / job's own id-pim-<role>), ONLY on
       the install's own vault, at resource scope -- never the resource group or the subscription; read back at the vault;
    2. per app / job: the value (Container Apps listSecrets, or the plain setting) into the vault -- the same value already
       there is reused -- and read back, compared by SHA-256 (never printed);
    3. with -WaitForIdleRuns a job is switched only between its runs (bounded; deferred otherwise, nothing is stopped);
    4. ONE update of the app / job: the secret becomes keyVaultUrl + identity, a plain setting becomes a secretRef;
    5. read back: the reference is on the app / job and the vault still holds the same value. A failed read-back puts the
       previous definitions back. The old value is never dropped before the vault read-back passed.
  A rollback record (JSON) holds the previous app / job secret definitions WITHOUT values (the values stay in the vault)
  and how to switch back. No secret value is printed, logged or written anywhere.

  -GrantOnly is THE SUPPORT-APP GRANT STEP (Invardia 2026-11-11): the install's own updater moves the secrets inside its
  update run, and the updater may not assign roles -- so this grants, ONCE per install and only at the install's own vault,
  Key Vault Secrets Officer to the updater (id-pim-updater) and Key Vault Secrets User to each identity that reads a secret
  to move; each read back. It reads, writes and switches no secret.

  Authentication: -UseSignedInAccount (the Invardia Support session open in this window, else your own browser sign-in)
  or an admin app's certificate (-AdminAppId -AdminCertThumbprint). The Key Vault writes need Key Vault Secrets Officer
  on the vault for whoever runs it. REST only: no command-line tool, no PowerShell module.

.PARAMETER SubscriptionId
  The subscription of the PIM install (explicit, always).
.PARAMETER ResourceGroup
  The resource group of the PIM install (its container apps, jobs and Key Vault).
.PARAMETER TenantId
  The tenant id.
.PARAMETER VaultName
  The install's own Key Vault (it must be in -ResourceGroup and use Azure RBAC). Default: the one vault of the group.
.PARAMETER Only
  Limit the move to these app / job names.
.PARAMETER Apply
  Move. Without it the script only plans.
.PARAMETER GrantOnly
  The Support-app grant step: the updater's Key Vault Secrets Officer and the readers' Key Vault Secrets User at the vault;
  no secret is moved (the updater moves them in its next update run). With -WhatIf: the grants it would make.
.PARAMETER WaitForIdleRuns
  Switch a job only when none of its executions runs (waits at most -IdleWaitMinutes, then that job is deferred).
.PARAMETER IdleWaitMinutes
  The bound of -WaitForIdleRuns per job (default 20).
.PARAMETER RbacWaitSeconds
  Wait this long after a NEW role assignment before the first switch (default 60).
.PARAMETER LogDir
  Where the plan and the rollback record are written as JSON.
.PARAMETER UseSignedInAccount
  Sign in as yourself (browser), or use the Invardia Support session open in this window.
.PARAMETER AdminAppId
  Automation: the admin application's client id (with -AdminCertThumbprint).
.PARAMETER AdminCertThumbprint
  Automation: the thumbprint of the admin application's certificate in the local machine store.

.EXAMPLE
  .\Move-PimSecretsToKeyVault.ps1 -TenantId <tenant id> -SubscriptionId <sub> -ResourceGroup <rg> -UseSignedInAccount
  The plan, read-only.
.EXAMPLE
  .\Move-PimSecretsToKeyVault.ps1 -TenantId <tenant id> -SubscriptionId <sub> -ResourceGroup <rg> -UseSignedInAccount -Apply -WaitForIdleRuns -LogDir C:\temp\skv
.EXAMPLE
  .\Move-PimSecretsToKeyVault.ps1 -TenantId <tenant id> -SubscriptionId <sub> -ResourceGroup <rg> -UseSignedInAccount -GrantOnly
  The Support-app grant step (the updater then moves the secrets in its update run).

.NOTES
  Requirements:
    PowerShell: 5.1 or 7.
    Role: Contributor (or Container Apps Contributor) on the install's resource group; User Access Administrator (or Role Based Access Control Administrator) and Key Vault Secrets Officer on the install's Key Vault.
    Hosts: login.microsoftonline.com, management.azure.com, *.vault.azure.net

.LINK
  https://invardia.com/docs/pim/scripts/Move-PimSecretsToKeyVault/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$TenantId,
    [string]$VaultName = '',
    [string[]]$Only = @(),
    [switch]$Apply,
    [switch]$GrantOnly,
    [switch]$WaitForIdleRuns,
    [int]$IdleWaitMinutes = 20,
    [int]$RbacWaitSeconds = 60,
    [string]$LogDir = '',
    [switch]$UseSignedInAccount,
    [string]$AdminAppId,
    [string]$AdminCertThumbprint,
    # TEST seams (tests\Test-PimSecretsToKeyVault.ps1): ARM, the Key Vault data plane, the wait
    [scriptblock]$Arm,
    [scriptblock]$Kv,
    [scriptblock]$Sleep
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SecretsToKeyVault.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                # -UseSignedInAccount: the Support session, else the browser

function Invoke-PimSkvKvSecret {
    # The Key Vault data plane over REST (PIM-Rest's one token client: the signed-in identity or the admin app). The seam.
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Url, [object]$Body)
    if ("$Method".ToUpperInvariant() -eq 'PUT') { return (Invoke-PimRest -Method PUT -Url $Url -Body $Body -Resource 'https://vault.azure.net' -MaxRetry 2) }
    return (Invoke-PimRest -Method GET -Url $Url -Resource 'https://vault.azure.net' -MaxRetry 2)
}

$null = Start-PimScriptRun -Script 'Move-PimSecretsToKeyVault'
try {
    function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
    $dry = [bool]$WhatIfPreference
    if ($GrantOnly -and $Apply) { throw '-GrantOnly and -Apply are two different runs: -GrantOnly grants (the updater then moves), -Apply moves by hand' }
    $act = [bool]($Apply -or $GrantOnly)
    $mode = if ($GrantOnly) { if ($dry) { 'GRANT, What if' } else { 'GRANT (the Support-app step)' } } elseif ($Apply -and -not $dry) { 'APPLY' } elseif ($Apply) { 'APPLY, What if' } else { 'PLAN, read-only' }
    Say "=== SEC-10 move secrets to Key Vault: $ResourceGroup ($mode) ===" 'Cyan'
    foreach ($p in @(@{ n = 'SubscriptionId'; v = $SubscriptionId }, @{ n = 'ResourceGroup'; v = $ResourceGroup }, @{ n = 'TenantId'; v = $TenantId })) {
        if (-not "$($p.v)".Trim()) { throw "-$($p.n) is required" }
    }
    if ($IdleWaitMinutes -lt 1 -or $IdleWaitMinutes -gt 240) { throw '-IdleWaitMinutes must be 1..240' }

    # --- identity (seams given = the offline test: no sign-in) -------------------------------------------------------------
    if (-not $Arm -or -not $Kv) {
        if ($UseSignedInAccount) {
            if ("$AdminAppId".Trim() -or "$AdminCertThumbprint".Trim()) { throw '-UseSignedInAccount cannot be combined with -AdminAppId/-AdminCertThumbprint' }
            $skvWho = Get-PimSignedInIdentity -TenantId $TenantId -SubscriptionId $SubscriptionId
            if (-not $skvWho.ok) { throw "$($skvWho.reason)" }
            Set-PimSignedInGlobals -TenantId $TenantId
            Say "  identity: $($skvWho.reason)" 'DarkGray'
        } else {
            if (-not "$AdminAppId".Trim() -or -not "$AdminCertThumbprint".Trim()) { throw 'supply -UseSignedInAccount (browser, or the Invardia Support session in this window), or -AdminAppId with -AdminCertThumbprint' }
            $global:PIM_TenantId = $TenantId; $global:PIM_ClientId = $AdminAppId; $global:PIM_CertThumbprint = $AdminCertThumbprint
            Say "  identity: app $AdminAppId (certificate)" 'DarkGray'
        }
    }
    if (-not $Arm)   { $Arm   = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } } }
    if (-not $Kv)    { $Kv    = { param($m, $u, $b) if ($null -ne $b) { Invoke-PimSkvKvSecret -Method $m -Url $u -Body $b } else { Invoke-PimSkvKvSecret -Method $m -Url $u } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not "$LogDir".Trim()) { $LogDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-secrets-to-keyvault' }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force -WhatIf:$false | Out-Null }
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')

    # --- read + plan (GET only) ----------------------------------------------------------------------------------------------
    $skvInstall = Read-PimSkvInstall -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $skvChoice = Get-PimSkvVaultChoice -Vaults @($skvInstall.vaults) -VaultName $VaultName
    $skvAssign = @()
    if ($skvChoice.ok) { $skvAssign = @(Read-PimSkvVaultAssignments -Arm $Arm -Scope (Get-PimSkvVaultScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $skvChoice.name)) }
    $plan = Get-PimSkvPlan -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Install $skvInstall -VaultName $VaultName -Assignments $skvAssign -Only $Only -WithWriter:$GrantOnly
    foreach ($l in @(Format-PimSkvPlanLines -Plan $plan -WhatIfPrefix:($dry -or -not $act) -WaitForIdleRuns:$WaitForIdleRuns -IdleWaitMinutes $IdleWaitMinutes)) {
        $col = if ($l -match '^REFUSED|: refused') { 'Yellow' } elseif ($l -match '^summary') { 'Cyan' } else { 'Gray' }
        Say "  $l" $col
    }
    if (-not $GrantOnly -and $skvChoice.ok -and @($plan.resources | Where-Object { $_.state -eq 'move' }).Count) {
        $skvRead = Test-PimSkvVaultReadable -Kv $Kv -VaultUri $skvChoice.uri
        if (-not $skvRead.ok) { Say "  vault data plane: $($skvRead.reason)" 'Yellow' } else { Say '  vault data plane: reachable by the signed-in identity' 'DarkGray' }
    }
    $planOut = Join-Path $LogDir "secrets-to-keyvault-plan-$stamp.json"
    $planJson = [ordered]@{ subscriptionId = $plan.subscriptionId; resourceGroup = $plan.resourceGroup; vault = [ordered]@{ name = $plan.vault.name; scope = $(if ($plan.vault.name) { Get-PimSkvVaultScope -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName $plan.vault.name } else { '' }) }
                            refusal = $plan.refusal; counts = $plan.counts; grants = @($plan.grants); writer = $plan.writer
                            resources = @($plan.resources | ForEach-Object { [ordered]@{ name = $_.name; kind = $_.kind; role = $_.role; identity = $_.identityName; state = $_.state; reason = $_.reason; effect = $_.effect
                                secrets = @($_.secrets | ForEach-Object { [ordered]@{ secret = $_.acaSecret; vaultSecret = $_.vaultSecret; keyVaultUrl = $_.vaultUrl } })
                                env = @($_.envs | ForEach-Object { [ordered]@{ container = $_.container; env = $_.env; newSecret = $_.acaSecret; vaultSecret = $_.vaultSecret; keyVaultUrl = $_.vaultUrl } })
                                kept = @($_.kept) } }) }
    Set-Content -LiteralPath $planOut -Value ($planJson | ConvertTo-Json -Depth 8) -Encoding UTF8 -WhatIf:$false
    Say "  plan written: $planOut (names only)" 'DarkGray'

    if ($plan.refusal) { Say "RESULT: REFUSED -- $($plan.refusal)" 'Yellow'; exit 1 }
    if (-not $act) { Say "`nPLAN ONLY -- nothing was changed. Grant for the updater with -GrantOnly (the Support-app step), or move by hand with -Apply (add -WaitForIdleRuns on a busy install)." 'Cyan'; exit 0 }
    if ($dry) { Say "What if: Performing the operation `"$(if ($GrantOnly) { 'grant the Key Vault rights' } else { 'move secrets to Key Vault references' })`" -- every step below is what WOULD happen; nothing is written." 'Yellow' }

    # --- apply ---------------------------------------------------------------------------------------------------------------
    $res = Invoke-PimSkvApply -Arm $Arm -Kv $Kv -Plan $plan -Sleep $Sleep -DryRun:$dry -WaitForIdleRuns:$WaitForIdleRuns -IdleWaitMinutes $IdleWaitMinutes -RbacWaitSeconds $RbacWaitSeconds -GrantOnly:$GrantOnly
    foreach ($g in @($res.grants)) { Say "  [grant] $($g.action): $($g.role) for $($g.identity) at $($g.scope)" 'Gray' }
    foreach ($r in @($res.resources)) {
        foreach ($s in @($r.steps)) { Say ("  [{0}] {1}{2}" -f $s.step, $s.what, $(if ($s.readBack) { "  ($($s.readBack))" } else { '' })) 'Gray' }
        Say "  RESULT $($r.resource) : $($r.state)$(if ($r.error) { ' -- ' + $r.error })" $(switch ($r.state) { 'done' { 'Green' } 'dry-run' { 'Yellow' } 'failed' { 'Red' } default { 'Yellow' } })
    }
    if (-not $dry -and -not $GrantOnly) {
        $recOut = Join-Path $LogDir "secrets-to-keyvault-rollback-$stamp.json"
        $recJson = [ordered]@{ generatedUtc = $res.generatedUtc; subscriptionId = $res.subscriptionId; resourceGroup = $res.resourceGroup; vault = $res.vault; state = $res.state; error = $res.error
                               note = 'previous app / job secret definitions WITHOUT values -- every moved value is in the vault secret named next to it'; grants = @($res.grants); resources = @($res.rollback) }
        Set-Content -LiteralPath $recOut -Value ($recJson | ConvertTo-Json -Depth 10) -Encoding UTF8
        Say "  rollback record written: $recOut (no values)" 'DarkGray'
    }
    Say "RESULT: $($res.state)$(if ($res.error) { ' -- ' + $res.error })" $(switch ($res.state) { 'done' { 'Green' } 'nothing-to-do' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } })
    if ($dry) { Say 'What if: nothing was changed.' 'Yellow' }
    if ($res.state -in @('failed', 'refused')) { exit 1 }
    exit 0
} finally {
    Stop-PimScriptRun -Script 'Move-PimSecretsToKeyVault'
}
