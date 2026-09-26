#Requires -Version 5.1
<#
.SYNOPSIS
    The DEPLOY PROFILE -- the parameters a successful Invoke-PimDeployAll -Apply ran with, saved so
    the community edition can be kept current with ONE command (Update-PimCommunity.ps1).

.DESCRIPTION
    Operator 2026-09-26: "update ... setup scripts so community version runs latest version". The
    README's update was "git pull, then re-run step 3 with the same parameters" -- a command of ~25
    parameters nobody keeps. After a successful -Apply the deploy writes them here; the updater pulls
    the latest release and re-runs the deploy with them.

    🔒 NEVER A SECRET. A parameter whose NAME says secret/password, and any value that carries a
    password (a SQL connection string with Password=), is left out and listed under 'omitted'. The
    deploy is certificate-only by design, so a normal community profile omits nothing. The
    certificate itself stays in the machine store; the profile holds its thumbprint and PEM path only.
    Run modes (-Apply / -WhatIf / common parameters) are never saved: the updater decides those.
#>

function Get-PimDeployProfileDir {
    $base = if ("$env:LOCALAPPDATA".Trim()) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
    Join-Path $base 'pim\deploy-profiles'
}

function ConvertTo-PimDeployProfile {
    <# PURE. Bound parameters -> @{ parameters = ordered; omitted = names left out because they carry a secret }. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Bound)
    $runModes = @('Apply', 'WhatIf', 'Confirm', 'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
        'ProgressAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
    $params = [ordered]@{}; $omitted = @()
    foreach ($k in @($Bound.Keys | Sort-Object)) {
        if ($runModes -contains $k) { continue }
        $v = $Bound[$k]
        if ("$k" -match '(?i)secret|password|pwd') { $omitted += "$k"; continue }
        if ($v -is [securestring]) { $omitted += "$k"; continue }
        if ($v -is [System.Management.Automation.SwitchParameter]) { $v = [bool]$v.IsPresent }
        $vals = @($v)
        if (@($vals | Where-Object { "$_" -match '(?i)(password|pwd)\s*=' }).Count) { $omitted += "$k"; continue }
        $params[$k] = if ($v -is [array]) { @($v | ForEach-Object { "$_" }) } elseif ($v -is [bool] -or $v -is [int] -or $v -is [long]) { $v } else { "$v" }
    }
    [pscustomobject]@{ parameters = $params; omitted = $omitted }
}

function Get-PimDeployProfilePath {
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ResourceGroup)
    $safe = ("$TenantId-$ResourceGroup" -replace '[^A-Za-z0-9._-]', '_')
    Join-Path (Get-PimDeployProfileDir) "$safe.json"
}

function Save-PimDeployProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Bound,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string]$Version = ''
    )
    $p = ConvertTo-PimDeployProfile -Bound $Bound
    $path = Get-PimDeployProfilePath -TenantId $TenantId -ResourceGroup $ResourceGroup
    $dir = Split-Path -Parent $path
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $doc = [ordered]@{ schema = 1; savedUtc = (Get-Date).ToUniversalTime().ToString('o'); version = "$Version"; parameters = $p.parameters; omitted = @($p.omitted) }
    [IO.File]::WriteAllText($path, ($doc | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    [pscustomobject]@{ path = $path; omitted = @($p.omitted) }
}

function Read-PimDeployProfile {
    <# The saved parameters as a hashtable ready to splat into Invoke-PimDeployAll. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $doc = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    if ("$($doc.schema)" -ne '1') { throw "deploy profile $Path has schema '$($doc.schema)', expected 1" }
    $h = @{}
    foreach ($p in $doc.parameters.PSObject.Properties) {
        $v = $p.Value
        # PS 5.1 ConvertFrom-Json hands an array back as ONE object -- assign, then enumerate.
        if ($v -is [array]) { $h[$p.Name] = [string[]]@($v | ForEach-Object { "$_" }) } else { $h[$p.Name] = $v }
    }
    [pscustomobject]@{ parameters = $h; omitted = @($doc.omitted | Where-Object { $_ }); version = "$($doc.version)"; savedUtc = "$($doc.savedUtc)" }
}
