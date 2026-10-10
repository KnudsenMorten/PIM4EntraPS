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
# signed-in path, tenant-pinned and verified).
if ($spec.signedIn) {
    . (Join-Path $PSScriptRoot '_PimSignedIn.ps1')
    Set-PimSignedInGlobals -TenantId "$($spec.signedIn.tenantId)"
    # 2026-10-10 (a customer's managed install opened a NEW browser sign-in in every step process and looked frozen): the
    # build signs in ONCE and hands this process short-lived ACCESS tokens per audience in PIM_HANDOFF_TOKENS (this
    # process's environment only -- never a file, never an argument). They answer first; an audience not handed over
    # falls back to the signed-in provider above.
    if ("$env:PIM_HANDOFF_TOKENS".Trim()) {
        try { $script:PimHandoff = "$env:PIM_HANDOFF_TOKENS" | ConvertFrom-Json } catch { $script:PimHandoff = $null }
        # kept in this process's environment on purpose: processes this step starts inherit it (the build clears it afterwards)
        if ($script:PimHandoff) {
            $script:PimHandoffFallback = $global:PIM_TokenProvider
            $global:PIM_TokenProvider = {
                param($Audience, $TenantId)
                $k = "$Audience".Trim().TrimEnd('/').ToLowerInvariant()
                foreach ($p in $script:PimHandoff.PSObject.Properties) { if ("$($p.Name)".TrimEnd('/').ToLowerInvariant() -eq $k -and "$($p.Value)".Trim()) { return "$($p.Value)" } }
                if ($script:PimHandoffFallback) { return (& $script:PimHandoffFallback $Audience $TenantId) }
                throw "no handed-over token for $Audience"
            }
        }
    }
}
# 100.41: the identity above IS this step's REST session. Saying so (PIM_SetupRestMode) keeps a ported step from opening its
# own (Connect-PimSetupRest with no credential would clear the build's certificate identity and fall to a browser sign-in).
if ("$($global:PIM_ClientId)".Trim() -and "$($global:PIM_CertThumbprint)$($global:PIM_ClientSecret)".Trim()) {
    $global:PIM_SetupRestMode = $(if ("$($global:PIM_CertThumbprint)".Trim()) { 'certificate' } else { 'secret' })
} elseif ($spec.signedIn) { $global:PIM_SetupRestMode = 'signedIn' }
# REQ 100.42 / framework 12.17 (owner 2026-10-09: "modern single connect only", no PowerShell modules): a step is NEVER given
# an Az PowerShell context. Every step authenticates through PIM-Rest's one token client with the identity in the globals
# above. A spec that still asks for one (an older runner) is refused rather than silently run without it.
if ($spec.PSObject.Properties['azPowerShell'] -and $spec.azPowerShell) {
    Write-Host 'STEP REFUSED: this step asks for an Az PowerShell context -- PIM no longer uses Az PowerShell modules (one REST connect path only). Run the build from the same release as this launcher.' -ForegroundColor Red
    exit 1
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
