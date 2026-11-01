#Requires -Version 7.0
<#
.SYNOPSIS
  APIDOC-1 (owner 2026-10-31: "all apis and mcp must be fully documented in gui and on invardia.com") -- GENERATE the PIM
  Manager's API + MCP reference from the code. Maintainer / release-host script: never run in a customer environment.

.DESCRIPTION
  The reading of the code lives in tools/setup/_PimApiReference.ps1 (the Manager uses the same library for its own
  Settings > API and MCP reference page): every route the router serves, with the role gate its body checks first (x-role),
  its Pro feature and x-internal; the MCP tools by RUNNING Get-PimManagerMcpTools on its own (no handler runs).

  TWO outputs, never mixed:
    -OutDir      the PUBLIC PROFILE -- the hand-over to invardia.com (owner 2026-11-01: "dont expose ways a hacker can gain
                 access to customer"; framework APIDOC-1 item 6). Deny by default: only the routine routes and MCP tools on
                 the reviewed allow-list in _PimApiReference.ps1, none of the left-out classes (emergency / break-glass /
                 restore, backups, support / diagnostics, API keys and every sign-in / secret route, security settings,
                 destructive / Tier-0, page mechanics) and none of Invardia's import words. Writes api.json, mcp.json,
                 README.txt, SHA256SUMS.txt (Invardia's shape, PIM 93.5).
    -FullOutDir  the FULL reference (every route and tool; what the signed-in Manager page shows): api-full.json,
                 mcp-full.json. Optional, for review. It is NEVER part of the hand-over: a -FullOutDir under a 'handover'
                 folder, or equal to -OutDir, is refused.
  Every text is checked before it is written: no host names, tenant / subscription GUIDs, e-mail addresses or secrets; the
  public profile also fails on a reviewed public entry that is not a route / tool or that matches a left-out class.

.EXAMPLE
  pwsh -NoProfile -File tools\setup\New-PimApiReference.ps1 -OutDir C:\ProgramData\Invardia\handover\apidoc\pim-manager\3.0.12
#>
[CmdletBinding()]
param([string]$OutDir = '', [string]$FullOutDir = '', [string]$Version = '', [switch]$PassThru)
$ErrorActionPreference = 'Stop'
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $Version) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
if ($FullOutDir) {
    $fo = [IO.Path]::GetFullPath($FullOutDir)
    if ($fo -match '(?i)[\\/]handover([\\/]|$)') { throw "-FullOutDir '$FullOutDir' is under a handover folder -- the full reference is never handed over (only -OutDir, the public profile, is)" }
    if ($OutDir -and $fo.TrimEnd('\', '/') -eq ([IO.Path]::GetFullPath($OutDir)).TrimEnd('\', '/')) { throw '-FullOutDir must not be -OutDir: the public hand-over never carries the full reference' }
}
. (Join-Path $PSScriptRoot '_PimApiReference.ps1')

$routes = Get-PimApiReferenceRoutes -SolutionRoot $sol
$desc = Get-PimApiRefDescriptions -SolutionRoot $sol

# ---------------------------------------------------------------------------------------------------------- the MCP tools
$mgrSrc = [IO.File]::ReadAllText((Join-Path $sol 'tools\pim-manager\Open-PimManager.ps1'))
$ast = [System.Management.Automation.Language.Parser]::ParseInput($mgrSrc, [ref]$null, [ref]$null)
# The MCP library is a Pro file (absent from the community payload): guarded, and without it there are no MCP tools to list.
$mcpLib = Join-Path $sol 'engine\mcp\PIM-Mcp.ps1'
$tools = @()
if (Test-Path -LiteralPath $mcpLib) {
    . $mcpLib
    $toolsFn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-PimManagerMcpTools' }, $true)
    function Test-PimManagerIsMspMaster { $true }   # the managing-tenant tools are documented too (listed only there)
    . ([scriptblock]::Create($toolsFn.Extent.Text))
    $tools = @(Get-PimManagerMcpTools)
}

$pub = New-PimApiReferenceDocument -Routes $routes -Tools $tools -Version $Version -Descriptions $desc -Profile Public
$full = New-PimApiReferenceDocument -Routes $routes -Tools $tools -Version $Version -Descriptions $desc -Profile Full

# ---------------------------------------------------------------------------------------------------------- check + write
$pubApi = $pub.api | ConvertTo-Json -Depth 30; $pubMcp = $pub.mcp | ConvertTo-Json -Depth 30
$fullApi = $full.api | ConvertTo-Json -Depth 30; $fullMcp = $full.mcp | ConvertTo-Json -Depth 30
$bad = @()
$bad += Test-PimApiReferenceClean -Name 'api.json' -Text $pubApi
$bad += Test-PimApiReferenceClean -Name 'mcp.json' -Text $pubMcp
$bad += Test-PimApiReferenceClean -Name 'api-full.json' -Text $fullApi
$bad += Test-PimApiReferenceClean -Name 'mcp-full.json' -Text $fullMcp
$bad += @($pub.conflicts | ForEach-Object { "public profile: $_" })
$bad = @($bad | Where-Object { $_ })
if ($bad.Count) { throw "the generated reference is NOT clean -- nothing written:`n  " + ($bad -join "`n  ") }

$lo = $pub.leftOut
$loText = (@($lo.Keys | ForEach-Object { "$_ $($lo[$_])" }) -join ', ')
if ($OutDir) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $utf8 = New-Object Text.UTF8Encoding($false)
    foreach ($stale in 'api-full.json', 'mcp-full.json') { $sp = Join-Path $OutDir $stale; if (Test-Path -LiteralPath $sp) { Remove-Item -LiteralPath $sp -Force } }
    [IO.File]::WriteAllText((Join-Path $OutDir 'api.json'), $pubApi, $utf8)
    [IO.File]::WriteAllText((Join-Path $OutDir 'mcp.json'), $pubMcp, $utf8)
    $readme = @"
PIM Manager $Version -- API and MCP reference (public profile)

api.json   OpenAPI 3.1: the routine routes of the PIM Manager API ($($pub.summary.routes) operations on $($pub.summary.paths) paths). Each
           operation names the PIM Manager role it needs (x-role). Paths are relative to the customer's own PIM Manager address.
mcp.json   the routine MCP tools: $($pub.summary.mcpTools) tools ($($pub.summary.mcpRead) read, $($pub.summary.mcpWrite) write), each with its input schema, the role
           it needs and the API route it runs. Writes go through the same checks as the page.

This is the public profile: $($pub.summary.routesLeftOut) of $($routes.Count) routes and $($pub.summary.mcpToolsLeftOut) of $($tools.Count) MCP tools are left out of it on purpose.
The complete reference, filtered to the person's role, is inside each PIM Manager (Settings > API and MCP reference).

Generated from the code of PIM Manager $Version by tools/setup/New-PimApiReference.ps1 (never a hand-kept list). Summaries
come from the curated tools/pim-manager/api-descriptions.json; code comments are never published.
"@
    [IO.File]::WriteAllText((Join-Path $OutDir 'README.txt'), ($readme -replace "`r`n", "`n"), $utf8)
    $sums = foreach ($n in 'api.json', 'mcp.json', 'README.txt') { "$((Get-FileHash -LiteralPath (Join-Path $OutDir $n) -Algorithm SHA256).Hash.ToLowerInvariant())  $n" }
    [IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), $utf8)
    Write-Host "API + MCP reference $Version (PUBLIC profile) written to $OutDir ($($pub.summary.routes) routes, $($pub.summary.mcpTools) MCP tools; left out: $loText)" -ForegroundColor Green
}
if ($FullOutDir) {
    New-Item -ItemType Directory -Force -Path $FullOutDir | Out-Null
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $FullOutDir 'api-full.json'), $fullApi, $utf8)
    [IO.File]::WriteAllText((Join-Path $FullOutDir 'mcp-full.json'), $fullMcp, $utf8)
    Write-Host "API + MCP reference $Version (FULL, not for hand-over) written to $FullOutDir ($($full.summary.routes) routes, $($full.summary.mcpTools) MCP tools; role unresolved: $($full.summary.roleUnresolved))" -ForegroundColor Green
}
if ($PassThru -or (-not $OutDir -and -not $FullOutDir)) {
    [pscustomobject]@{ summary = $pub.summary; fullSummary = $full.summary; leftOut = $pub.leftOut; leftOutRoutes = $pub.leftOutRoutes
                       api = $pub.api; mcp = $pub.mcp; fullApi = $full.api; fullMcp = $full.mcp; routes = $routes }
}
