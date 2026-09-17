#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- run ONE step of the one-shot MSP build (Invoke-PimMspBuild.ps1) in its own process, on the host the step
    needs (Windows PowerShell 5.1 for the SqlClient steps, pwsh for the rest).

.DESCRIPTION
    Arguments arrive in a JSON file (so arrays and switches survive a process boundary without command-line quoting):
        { "args": { "Name": value, ... }, "switches": ["Apply", ...], "globals": { "PIM_TenantId": "...", ... } }
    The runner writes that file into its restricted per-run directory and deletes it as soon as this process exits.
    When -OutFile is given, the step's last non-empty STRING pipeline output is written there (the minted read link is
    a pipeline value, never a log line) -- same directory, same lifetime.
    Exit code: the step's own exit code; 1 when it threw.
#>
param(
    [Parameter(Mandatory)][string]$Script,
    [Parameter(Mandatory)][string]$ArgsFile,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
$spec = Get-Content -LiteralPath $ArgsFile -Raw | ConvertFrom-Json
$splat = @{}
if ($spec.args) {
    foreach ($p in $spec.args.PSObject.Properties) {
        $v = $p.Value
        if ($v -is [System.Array]) { $v = [string[]]@($v | ForEach-Object { "$_" }) }
        $splat[$p.Name] = $v
    }
}
foreach ($s in @($spec.switches)) { if ("$s".Trim()) { $splat["$s"] = $true } }
if ($spec.globals) { foreach ($g in $spec.globals.PSObject.Properties) { Set-Variable -Scope Global -Name $g.Name -Value "$($g.Value)" } }
# 71.33 -- SIGNED-IN build: no application identity in this process at all (the engine token helpers then take the
# signed-in az path, tenant-pinned and verified), and an Az PowerShell step is connected with the signed-in user's
# tokens, minted from az IN MEMORY for this process only -- never written, never printed.
if ($spec.signedIn) {
    . (Join-Path $PSScriptRoot '_PimSignedIn.ps1')
    Set-PimSignedInGlobals -TenantId "$($spec.signedIn.tenantId)"
}
if ($spec.azPowerShell -and "$($spec.azPowerShell.mode)" -eq 'signedIn') {
    $c = $spec.azPowerShell
    $id = Get-PimSignedInIdentity -TenantId $c.tenantId -SubscriptionId $c.subscriptionId
    if (-not $id.ok) { Write-Host "STEP REFUSED: $($id.reason)" -ForegroundColor Red; exit 1 }
    $ErrorActionPreference = 'Continue'
    $armTok = "$(((az account get-access-token --subscription $c.subscriptionId --resource https://management.azure.com/ -o json 2>$null) | Out-String | ConvertFrom-Json).accessToken)"
    $graphTok = "$(((az account get-access-token --subscription $c.subscriptionId --resource https://graph.microsoft.com/ -o json 2>$null) | Out-String | ConvertFrom-Json).accessToken)"
    $ErrorActionPreference = 'Stop'
    foreach ($t in @($armTok, $graphTok)) { $v = Test-PimSignedInToken -Token $t -TenantId $c.tenantId; if (-not $v.ok) { Write-Host "STEP REFUSED: $($v.reason)" -ForegroundColor Red; exit 1 } }
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -AccessToken $armTok -MicrosoftGraphAccessToken $graphTok -AccountId $id.userName -Tenant $c.tenantId -Subscription $c.subscriptionId -Scope Process -WarningAction SilentlyContinue | Out-Null
    $armTok = $null; $graphTok = $null
    $ctx = Get-AzContext
    if ("$($ctx.Tenant.Id)" -ne "$($c.tenantId)" -or "$($ctx.Subscription.Id)" -ne "$($c.subscriptionId)") { Write-Host "STEP REFUSED: Az PowerShell context is $($ctx.Tenant.Id)/$($ctx.Subscription.Id), expected $($c.tenantId)/$($c.subscriptionId)" -ForegroundColor Red; exit 1 }
}
# A step written against Az PowerShell (not az CLI) gets a process-scoped CERTIFICATE context first.
elseif ($spec.azPowerShell) {
    $c = $spec.azPowerShell
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -ServicePrincipal -Tenant $c.tenantId -ApplicationId $c.clientId -CertificateThumbprint $c.certThumbprint -Subscription $c.subscriptionId -Scope Process -WarningAction SilentlyContinue | Out-Null
    $ctx = Get-AzContext
    if ("$($ctx.Tenant.Id)" -ne "$($c.tenantId)" -or "$($ctx.Subscription.Id)" -ne "$($c.subscriptionId)") { Write-Host "STEP REFUSED: Az PowerShell context is $($ctx.Tenant.Id)/$($ctx.Subscription.Id), expected $($c.tenantId)/$($c.subscriptionId)" -ForegroundColor Red; exit 1 }
}
$global:LASTEXITCODE = 0
try {
    $out = @(& $Script @splat)
    $code = if ($LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
} catch {
    Write-Host "STEP THREW: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) { Write-Host "  at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red }
    exit 1
}
if ("$OutFile".Trim()) {
    $last = @($out | Where-Object { $_ -is [string] -and "$_".Trim() }) | Select-Object -Last 1
    [IO.File]::WriteAllText($OutFile, "$last", [Text.Encoding]::UTF8)
}
exit $code
